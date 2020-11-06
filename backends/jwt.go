package backends

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	h "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWT struct {
	mode    string
	LocalDB string

	Postgres       Postgres
	Mysql          Mysql
	Secret         string
	UserQuery      string
	SuperuserQuery string
	AclQuery       string

	UserUri            string
	SuperuserUri       string
	AclUri             string
	Host               string
	Port               string
	WithTLS            bool
	VerifyPeer         bool
	SkipUserExpiration bool
	SkipACLExpiration  bool

	ParamsMode   string
	ResponseMode string

	UserField string

	Client *h.Client

	hasher hashing.HashComparer

	userScript      string
	superuserScript string
	aclScript       string

	jsStackDepthLimit int
	jsMsMaxDuration   int64

	jsUserScript      string
	jsSuperuserScript string
	jsAclScript       string

	jsRunner *JsRunner
}

// Claims defines the struct containing the token claims. StandardClaim's Subject field should contain the username, unless an opt is set to support Username field.
type Claims struct {
	jwt.StandardClaims
	// If set, Username defines the identity of the user.
	Username string `json:"username"`
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

const (
	remoteMode = "remote"
	localMode  = "local"
	jsMode     = "js"
)

func NewJWT(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (*JWT, error) {
	log.SetLevel(logLevel)

	var jwt = &JWT{
		WithTLS:           false,
		VerifyPeer:        false,
		ResponseMode:      "status",
		ParamsMode:        "json",
		LocalDB:           "postgres",
		UserField:         "Subject",
		hasher:            hasher,
		jsMsMaxDuration:   100,
		jsStackDepthLimit: 32,
	}

	if userField, ok := authOpts["jwt_userfield"]; ok && userField == "Username" {
		jwt.UserField = userField
	} else {
		log.Debugln("JWT user field not present or incorrect, defaulting to Subject field.")
	}

	if skipUserExpiration, ok := authOpts["jwt_skip_user_expiration"]; ok && skipUserExpiration == "true" {
		jwt.SkipUserExpiration = true
	}

	if skipACLExpiration, ok := authOpts["jwt_skip_acl_expiration"]; ok && skipACLExpiration == "true" {
		jwt.SkipACLExpiration = true
	}

	var err error
	switch authOpts["jwt_mode"] {
	case jsMode:
		jwt.mode = jsMode
		err = configureJsJWT(jwt, authOpts)
	case localMode:
		jwt.mode = localMode
		err = configureLocalJWT(jwt, authOpts, logLevel, hasher)
	case remoteMode:
		jwt.mode = remoteMode
		err = configureRemoteJWT(jwt, authOpts)
	default:
		err = errors.New("unknown JWT mode")
	}

	if err != nil {
		return nil, err
	}

	return jwt, nil
}

func configureJsJWT(jwt *JWT, authOpts map[string]string) error {
	if stackLimit, ok := authOpts["jwt_js_stack_depth_limit"]; ok {
		limit, err := strconv.ParseInt(stackLimit, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to 32", stackLimit)
		} else {
			jwt.jsStackDepthLimit = int(limit)
		}
	}

	if maxDuration, ok := authOpts["jwt_js_ms_max_duration"]; ok {
		duration, err := strconv.ParseInt(maxDuration, 10, 64)
		if err != nil {
			log.Errorf("invalid stack depth limit %s, defaulting to 32", maxDuration)
		} else {
			jwt.jsMsMaxDuration = duration
		}
	}

	if userScriptPath, ok := authOpts["jwt_js_user_script_path"]; ok {
		script, err := loadScript(userScriptPath)
		if err != nil {
			return err
		}

		jwt.userScript = script
	} else {
		return errors.New("missing jwt_js_user_script_path")
	}

	if superuserScriptPath, ok := authOpts["jwt_superuser_script_path"]; ok {
		script, err := loadScript(superuserScriptPath)
		if err != nil {
			return err
		}

		jwt.superuserScript = script
	}

	if aclScriptPath, ok := authOpts["jwt_js_acl_script_path"]; ok {
		script, err := loadScript(aclScriptPath)
		if err != nil {
			return err
		}

		jwt.aclScript = script
	}

	jwt.jsRunner = NewJsRunner(jwt.jsStackDepthLimit, jwt.jsMsMaxDuration)

	return nil
}

func configureLocalJWT(jwt *JWT, authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) error {
	missingOpts := ""
	localOk := true

	if secret, ok := authOpts["jwt_secret"]; ok {
		jwt.Secret = secret
	} else {
		return errors.New("JWT backend error: missing jwt secret")
	}

	if userQuery, ok := authOpts["jwt_userquery"]; ok {
		jwt.UserQuery = userQuery
	} else {
		localOk = false
		missingOpts += " jwt_userquery"
	}

	if superuserQuery, ok := authOpts["jwt_superquery"]; ok {
		jwt.SuperuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["jwt_aclquery"]; ok {
		jwt.AclQuery = aclQuery
	}

	if localDB, ok := authOpts["jwt_db"]; ok {
		jwt.LocalDB = localDB
	}

	if !localOk {
		return errors.Errorf("JWT backend error: missing local options: %s", missingOpts)
	}

	if jwt.LocalDB == "mysql" {
		//Try to create a mysql backend with these custom queries
		mysql, err := NewMysql(authOpts, logLevel, hasher)
		if err != nil {
			return errors.Errorf("JWT backend error: couldn't create mysql connector for local jwt: %s", err)
		}
		mysql.UserQuery = jwt.UserQuery
		mysql.SuperuserQuery = jwt.SuperuserQuery
		mysql.AclQuery = jwt.AclQuery

		jwt.Mysql = mysql
	} else {
		//Try to create a postgres backend with these custom queries.
		postgres, err := NewPostgres(authOpts, logLevel, hasher)
		if err != nil {
			return errors.Errorf("JWT backend error: couldn't create postgres connector for local jwt: %s", err)
		}
		postgres.UserQuery = jwt.UserQuery
		postgres.SuperuserQuery = jwt.SuperuserQuery
		postgres.AclQuery = jwt.AclQuery

		jwt.Postgres = postgres
	}

	return nil
}

func configureRemoteJWT(jwt *JWT, authOpts map[string]string) error {
	missingOpts := ""
	remoteOk := true

	if responseMode, ok := authOpts["jwt_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			jwt.ResponseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["jwt_params_mode"]; ok {
		if paramsMode == "form" {
			jwt.ParamsMode = paramsMode
		}
	}

	if userUri, ok := authOpts["jwt_getuser_uri"]; ok {
		jwt.UserUri = userUri
	} else {
		remoteOk = false
		missingOpts += " jwt_getuser_uri"
	}

	if superuserUri, ok := authOpts["jwt_superuser_uri"]; ok {
		jwt.SuperuserUri = superuserUri
	}

	if aclUri, ok := authOpts["jwt_aclcheck_uri"]; ok {
		jwt.AclUri = aclUri
	} else {
		remoteOk = false
		missingOpts += " jwt_aclcheck_uri"
	}

	if hostname, ok := authOpts["jwt_host"]; ok {
		jwt.Host = hostname
	} else {
		remoteOk = false
		missingOpts += " jwt_host"
	}

	if port, ok := authOpts["jwt_port"]; ok {
		jwt.Port = port
	} else {
		remoteOk = false
		missingOpts += " jwt_port"
	}

	if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
		jwt.WithTLS = true
	}

	if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
		jwt.VerifyPeer = true
	}

	if !remoteOk {
		return errors.Errorf("JWT backend error: missing remote options: %s", missingOpts)
	}

	jwt.Client = &h.Client{Timeout: 5 * time.Second}

	if !jwt.VerifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		jwt.Client.Transport = tr
	}

	return nil
}

//GetUser authenticates a given user.
func (o JWT) GetUser(token, password, clientid string) bool {
	switch o.mode {
	case jsMode:
		params := map[string]interface{}{
			"username": token,
		}

		granted, err := o.jsRunner.runScript(o.userScript, params)
		if err != nil {
			log.Errorf("js error: %s", err)
		}

		return granted
	case localMode:
		claims, err := o.getClaims(token, o.SkipUserExpiration)

		if err != nil {
			log.Printf("jwt get user error: %s", err)
			return false
		}

		if o.UserField == "Username" {
			return o.getLocalUser(claims.Username)
		}
		return o.getLocalUser(claims.Subject)
	case remoteMode:
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return o.jwtRequest(o.Host, o.UserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	return false
}

//GetSuperuser checks if the given user is a superuser.
func (o JWT) GetSuperuser(token string) bool {
	switch o.mode {
	case jsMode:
		params := map[string]interface{}{
			"username": token,
		}

		granted, err := o.jsRunner.runScript(o.superuserScript, params)
		if err != nil {
			log.Errorf("js error: %s", err)
		}

		return granted
	case localMode:
		if o.SuperuserQuery == "" {
			return false
		}
		claims, err := o.getClaims(token, o.SkipUserExpiration)

		if err != nil {
			log.Debugf("jwt get superuser error: %s", err)
			return false
		}
		//Now check against db
		if o.UserField == "Username" {
			if o.LocalDB == "mysql" {
				return o.Mysql.GetSuperuser(claims.Username)
			} else {
				return o.Postgres.GetSuperuser(claims.Username)
			}
		}

		if o.LocalDB == "mysql" {
			return o.Mysql.GetSuperuser(claims.Subject)
		} else {
			return o.Postgres.GetSuperuser(claims.Subject)
		}
	case remoteMode:
		if o.SuperuserUri == "" {
			return false
		}
		var dataMap map[string]interface{}
		var urlValues = url.Values{}
		return o.jwtRequest(o.Host, o.SuperuserUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	return false
}

//CheckAcl checks user authorization.
func (o JWT) CheckAcl(token, topic, clientid string, acc int32) bool {
	switch o.mode {
	case jsMode:
		params := map[string]interface{}{
			"username": token,
			"clientid": clientid,
			"acc":      acc,
		}

		granted, err := o.jsRunner.runScript(o.aclScript, params)
		if err != nil {
			log.Errorf("js error: %s", err)
		}

		return granted
	case localMode:
		if o.AclQuery == "" {
			return true
		}
		claims, err := o.getClaims(token, o.SkipACLExpiration)

		if err != nil {
			log.Debugf("jwt check acl error: %s", err)
			return false
		}
		//Now check against the db.
		if o.UserField == "Username" {
			if o.LocalDB == "mysql" {
				return o.Mysql.CheckAcl(claims.Username, topic, clientid, acc)
			} else {
				return o.Postgres.CheckAcl(claims.Username, topic, clientid, acc)
			}
		}
		if o.LocalDB == "mysql" {
			return o.Mysql.CheckAcl(claims.Subject, topic, clientid, acc)
		} else {
			return o.Postgres.CheckAcl(claims.Subject, topic, clientid, acc)
		}
	case remoteMode:
		dataMap := map[string]interface{}{
			"clientid": clientid,
			"topic":    topic,
			"acc":      acc,
		}
		var urlValues = url.Values{
			"clientid": []string{clientid},
			"topic":    []string{topic},
			"acc":      []string{strconv.Itoa(int(acc))},
		}
		return o.jwtRequest(o.Host, o.AclUri, token, o.WithTLS, o.VerifyPeer, dataMap, o.Port, o.ParamsMode, o.ResponseMode, urlValues)
	}

	return false
}

func (o JWT) jwtRequest(host, uri, token string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port, paramsMode, responseMode string, urlValues url.Values) bool {

	// Don't do the request if the client is nil.
	if o.Client == nil {
		return false
	}

	tlsStr := "http://"

	if withTLS {
		tlsStr = "https://"
	}

	fullUri := fmt.Sprintf("%s%s%s", tlsStr, host, uri)
	if port != "" {
		fullUri = fmt.Sprintf("%s%s:%s%s", tlsStr, host, port, uri)
	}

	var resp *http.Response
	var err error
	var req *http.Request

	if paramsMode == "json" {
		dataJson, err := json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false
		}

		contentReader := bytes.NewReader(dataJson)
		req, err = http.NewRequest("POST", fullUri, contentReader)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest("POST", fullUri, strings.NewReader(urlValues.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(urlValues.Encode())))

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err = o.Client.Do(req)

	if err != nil {
		log.Errorf("error: %v", err)
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Errorf("read error: %s", err)
		return false
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Infof("error code: %d", resp.StatusCode)
		return false
	}

	if responseMode == "text" {

		//For test response, we expect "ok" or an error message.
		if string(body) != "ok" {
			log.Infof("api error: %s", string(body))
			return false
		}

	} else if responseMode == "json" {

		//For json response, we expect Ok and Error fields.
		response := Response{Ok: false, Error: ""}
		err = json.Unmarshal(body, &response)

		if err != nil {
			log.Errorf("unmarshal error: %s", err)
			return false
		}

		if !response.Ok {
			log.Infof("api error: %s", response.Error)
			return false
		}

	}

	log.Debugf("jwt request approved for %s", token)
	return true

}

//GetName returns the backend's name
func (o JWT) GetName() string {
	return "JWT"
}

func (o JWT) getLocalUser(username string) bool {
	//If there's no user query, return false.
	if o.UserQuery == "" {
		return false
	}

	var count sql.NullInt64
	var err error
	if o.LocalDB == "mysql" {
		err = o.Mysql.DB.Get(&count, o.UserQuery, username)
	} else {
		err = o.Postgres.DB.Get(&count, o.UserQuery, username)
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

func (o JWT) getClaims(tokenStr string, skipExpiration bool) (*Claims, error) {

	jwtToken, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(o.Secret), nil
	})

	expirationError := false
	if err != nil {
		if !skipExpiration {
			log.Debugf("jwt parse error: %s", err)
			return nil, err
		}

		if v, ok := err.(*jwt.ValidationError); ok && v.Errors == jwt.ValidationErrorExpired {
			expirationError = true
		}
	}

	if !jwtToken.Valid && !expirationError {
		return nil, errors.New("jwt invalid token")
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok {
		// no need to use a static error, this should never happen
		log.Debugf("api/auth: expected *Claims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}

//Halt closes any db connection.
func (o JWT) Halt() {
	if o.Postgres != (Postgres{}) && o.Postgres.DB != nil {
		err := o.Postgres.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	} else if o.Mysql != (Mysql{}) && o.Mysql.DB != nil {
		err := o.Mysql.DB.Close()
		if err != nil {
			log.Errorf("JWT cleanup error: %s", err)
		}
	}
}
