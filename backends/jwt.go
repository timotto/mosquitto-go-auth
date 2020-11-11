package backends

import (
	jwtGo "github.com/dgrijalva/jwt-go"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type JWT struct {
	mode    string
	checker jwtChecker
}

type jwtChecker interface {
	GetUser(username string) bool
	GetSuperuser(username string) bool
	CheckAcl(username, topic, clientid string, acc int32) bool
	Halt()
}

// Claims defines the struct containing the token claims.
// StandardClaim's Subject field should contain the username, unless an opt is set to support Username field.
type Claims struct {
	jwtGo.StandardClaims
	// If set, Username defines the identity of the user.
	Username string `json:"username"`
}

const (
	remoteMode = "remote"
	localMode  = "local"
	jsMode     = "js"
)

func NewJWT(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (*JWT, error) {
	log.SetLevel(logLevel)

	jwt := &JWT{}

	var err error
	var checker jwtChecker

	switch authOpts["jwt_mode"] {
	case jsMode:
		jwt.mode = jsMode
		checker, err = NewJsJWTChecker(authOpts)
	case localMode:
		jwt.mode = localMode
		checker, err = NewLocalJWTChecker(authOpts, logLevel, hasher)
	case remoteMode:
		jwt.mode = remoteMode
		checker, err = NewRemoteJWTChecker(authOpts)
	default:
		err = errors.New("unknown JWT mode")
	}

	if err != nil {
		return nil, err
	}

	jwt.checker = checker

	return jwt, nil
}

//GetUser authenticates a given user.
func (o *JWT) GetUser(token, password, clientid string) bool {
	return o.checker.GetUser(token)
}

//GetSuperuser checks if the given user is a superuser.
func (o *JWT) GetSuperuser(token string) bool {
	return o.checker.GetSuperuser(token)
}

//CheckAcl checks user authorization.
func (o *JWT) CheckAcl(token, topic, clientid string, acc int32) bool {
	return o.checker.CheckAcl(token, topic, clientid, acc)
}

//GetName returns the backend's name
func (o *JWT) GetName() string {
	return "JWT"
}

//Halt closes any db connection.
func (o *JWT) Halt() {
	o.checker.Halt()
}

func getJWTClaims(secret string, tokenStr string, skipExpiration bool) (*Claims, error) {

	jwtToken, err := jwtGo.ParseWithClaims(tokenStr, &Claims{}, func(token *jwtGo.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	expirationError := false
	if err != nil {
		if !skipExpiration {
			log.Debugf("jwt parse error: %s", err)
			return nil, err
		}

		if v, ok := err.(*jwtGo.ValidationError); ok && v.Errors == jwtGo.ValidationErrorExpired {
			expirationError = true
		}
	}

	if !jwtToken.Valid && !expirationError {
		return nil, errors.New("jwt invalid token")
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok {
		log.Debugf("jwt error: expected *Claims, got %T", jwtToken.Claims)
		return nil, errors.New("got strange claims")
	}

	return claims, nil
}
