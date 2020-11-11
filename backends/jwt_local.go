package backends

import (
	"database/sql"

	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type localJWTChecker struct {
	db                 string
	postgres           Postgres
	mysql              Mysql
	secret             string
	userQuery          string
	superuserQuery     string
	aclQuery           string
	hasher             hashing.HashComparer
	userField          string
	skipUserExpiration bool
	skipACLExpiration  bool
}

const (
	mysqlDB    = "mysql"
	postgresDB = "postgres"
)

// NewLocalJWTChecker initializes a checker with a local DB.
func NewLocalJWTChecker(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (jwtChecker, error) {
	checker := &localJWTChecker{
		hasher:    hasher,
		db:        postgresDB,
		userField: "Subject",
	}

	missingOpts := ""
	localOk := true

	if secret, ok := authOpts["jwt_secret"]; ok {
		checker.secret = secret
	} else {
		return nil, errors.New("JWT backend error: missing jwt secret")
	}

	if userQuery, ok := authOpts["jwt_userquery"]; ok {
		checker.userQuery = userQuery
	} else {
		localOk = false
		missingOpts += " jwt_userquery"
	}

	if superuserQuery, ok := authOpts["jwt_superquery"]; ok {
		checker.superuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["jwt_aclquery"]; ok {
		checker.aclQuery = aclQuery
	}

	if db, ok := authOpts["jwt_db"]; ok {
		checker.db = db
	}

	if userField, ok := authOpts["jwt_userfield"]; ok && userField == "Username" {
		checker.userField = userField
	} else {
		log.Debugln("JWT user field not present or incorrect, defaulting to Subject field.")
	}

	if !localOk {
		return nil, errors.Errorf("JWT backend error: missing local options: %s", missingOpts)
	}

	if checker.db == mysqlDB {
		//Try to create a mysql backend with these custom queries
		mysql, err := NewMysql(authOpts, logLevel, hasher)
		if err != nil {
			return nil, errors.Errorf("JWT backend error: couldn't create mysql connector for local jwt: %s", err)
		}

		mysql.UserQuery = checker.userQuery
		mysql.SuperuserQuery = checker.superuserQuery
		mysql.AclQuery = checker.aclQuery

		checker.mysql = mysql

		return checker, nil
	}

	//Try to create a postgres backend with these custom queries.
	postgres, err := NewPostgres(authOpts, logLevel, hasher)
	if err != nil {
		return nil, errors.Errorf("JWT backend error: couldn't create postgres connector for local jwt: %s", err)
	}

	postgres.UserQuery = checker.userQuery
	postgres.SuperuserQuery = checker.superuserQuery
	postgres.AclQuery = checker.aclQuery

	checker.postgres = postgres

	return checker, nil
}

func (o *localJWTChecker) GetUser(username string) bool {
	claims, err := getJWTClaims(o.secret, username, o.skipUserExpiration)

	if err != nil {
		log.Printf("jwt get user error: %s", err)
		return false
	}

	if o.userField == "Username" {
		return o.getLocalUser(claims.Username)
	}

	return o.getLocalUser(claims.Subject)
}

func (o *localJWTChecker) GetSuperuser(username string) bool {
	if o.superuserQuery == "" {
		return false
	}
	claims, err := getJWTClaims(o.secret, username, o.skipUserExpiration)

	if err != nil {
		log.Debugf("jwt get superuser error: %s", err)
		return false
	}
	//Now check against db
	if o.userField == "Username" {
		if o.db == mysqlDB {
			return o.mysql.GetSuperuser(claims.Username)
		}

		return o.postgres.GetSuperuser(claims.Username)
	}

	if o.db == mysqlDB {
		return o.mysql.GetSuperuser(claims.Subject)
	}

	return o.postgres.GetSuperuser(claims.Subject)
}

func (o *localJWTChecker) CheckAcl(username, topic, clientid string, acc int32) bool {
	if o.aclQuery == "" {
		return true
	}
	claims, err := getJWTClaims(o.secret, username, o.skipACLExpiration)

	if err != nil {
		log.Debugf("jwt check acl error: %s", err)
		return false
	}

	if o.userField == "Username" {
		if o.db == mysqlDB {
			return o.mysql.CheckAcl(claims.Username, topic, clientid, acc)
		}

		return o.postgres.CheckAcl(claims.Username, topic, clientid, acc)
	}

	if o.db == mysqlDB {
		return o.mysql.CheckAcl(claims.Subject, topic, clientid, acc)
	}

	return o.postgres.CheckAcl(claims.Subject, topic, clientid, acc)
}

func (o *localJWTChecker) Halt() {
	if o.postgres != (Postgres{}) && o.postgres.DB != nil {
		err := o.postgres.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	} else if o.mysql != (Mysql{}) && o.mysql.DB != nil {
		err := o.mysql.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	}
}

func (o *localJWTChecker) getLocalUser(username string) bool {

	if o.userQuery == "" {
		return false
	}

	var count sql.NullInt64
	var err error
	if o.db == mysqlDB {
		err = o.mysql.DB.Get(&count, o.userQuery, username)
	} else {
		err = o.postgres.DB.Get(&count, o.userQuery, username)
	}

	if err != nil {
		log.Debugf("local JWT get user error: %s", err)
		return false
	}

	if !count.Valid {
		log.Debugf("local JWT get user error: user %s not found", username)
		return false
	}

	if count.Int64 > 0 {
		return true
	}

	return false
}
