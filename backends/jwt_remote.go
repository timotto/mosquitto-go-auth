package backends

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	h "net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type remoteJWTChecker struct {
	userUri      string
	superuserUri string
	aclUri       string
	host         string
	port         string
	withTLS      bool
	verifyPeer   bool

	paramsMode   string
	responseMode string

	client *h.Client
}

type Response struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

func NewRemoteChecker(authOpts map[string]string) (jwtChecker, error) {
	var checker = &remoteJWTChecker{
		withTLS:      false,
		verifyPeer:   false,
		responseMode: "status",
		paramsMode:   "json",
	}

	missingOpts := ""
	remoteOk := true

	if responseMode, ok := authOpts["jwt_response_mode"]; ok {
		if responseMode == "text" || responseMode == "json" {
			checker.responseMode = responseMode
		}
	}

	if paramsMode, ok := authOpts["jwt_params_mode"]; ok {
		if paramsMode == "form" {
			checker.paramsMode = paramsMode
		}
	}

	if userUri, ok := authOpts["jwt_getuser_uri"]; ok {
		checker.userUri = userUri
	} else {
		remoteOk = false
		missingOpts += " jwt_getuser_uri"
	}

	if superuserUri, ok := authOpts["jwt_superuser_uri"]; ok {
		checker.superuserUri = superuserUri
	}

	if aclUri, ok := authOpts["jwt_aclcheck_uri"]; ok {
		checker.aclUri = aclUri
	} else {
		remoteOk = false
		missingOpts += " jwt_aclcheck_uri"
	}

	if hostname, ok := authOpts["jwt_host"]; ok {
		checker.host = hostname
	} else {
		remoteOk = false
		missingOpts += " jwt_host"
	}

	if port, ok := authOpts["jwt_port"]; ok {
		checker.port = port
	} else {
		remoteOk = false
		missingOpts += " jwt_port"
	}

	if withTLS, ok := authOpts["jwt_with_tls"]; ok && withTLS == "true" {
		checker.withTLS = true
	}

	if verifyPeer, ok := authOpts["jwt_verify_peer"]; ok && verifyPeer == "true" {
		checker.verifyPeer = true
	}

	if !remoteOk {
		return nil, errors.Errorf("JWT backend error: missing remote options: %s", missingOpts)
	}

	checker.client = &h.Client{Timeout: 5 * time.Second}

	if !checker.verifyPeer {
		tr := &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		checker.client.Transport = tr
	}

	return checker, nil
}

func (o *remoteJWTChecker) GetUser(username string) bool {
	var dataMap map[string]interface{}
	var urlValues = url.Values{}
	return o.jwtRequest(o.host, o.userUri, username, o.withTLS, o.verifyPeer, dataMap, o.port, o.paramsMode, o.responseMode, urlValues)
}

func (o *remoteJWTChecker) GetSuperuser(username string) bool {
	if o.superuserUri == "" {
		return false
	}
	var dataMap map[string]interface{}
	var urlValues = url.Values{}
	return o.jwtRequest(o.host, o.superuserUri, username, o.withTLS, o.verifyPeer, dataMap, o.port, o.paramsMode, o.responseMode, urlValues)
}

func (o *remoteJWTChecker) CheckAcl(token, topic, clientid string, acc int32) bool {
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
	return o.jwtRequest(o.host, o.aclUri, token, o.withTLS, o.verifyPeer, dataMap, o.port, o.paramsMode, o.responseMode, urlValues)
}

func (o *remoteJWTChecker) Halt() {
	// NO-OP
}

func (o *remoteJWTChecker) jwtRequest(host, uri, token string, withTLS, verifyPeer bool, dataMap map[string]interface{}, port, paramsMode, responseMode string, urlValues url.Values) bool {

	// Don't do the request if the client is nil.
	if o.client == nil {
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

	var resp *h.Response
	var err error
	var req *h.Request

	if paramsMode == "json" {
		dataJson, err := json.Marshal(dataMap)

		if err != nil {
			log.Errorf("marshal error: %s", err)
			return false
		}

		contentReader := bytes.NewReader(dataJson)
		req, err = h.NewRequest("POST", fullUri, contentReader)

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = h.NewRequest("POST", fullUri, strings.NewReader(urlValues.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Content-Length", strconv.Itoa(len(urlValues.Encode())))

		if err != nil {
			log.Errorf("req error: %s", err)
			return false
		}
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err = o.client.Do(req)

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
