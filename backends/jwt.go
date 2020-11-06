package backends

import (
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
		checker, err = NewRemoteChecker(authOpts)
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
