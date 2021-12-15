package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	resterr "github.com/leslesnoa/bookstore_oauth-go/utils/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-User-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8083",
		Timeout: 200 * time.Millisecond,
	}
)

type oauthClient struct {
}

type oauthInterface interface {
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) *resterr.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	// QueryParameter取得。example: http://api.bookstore.com/resource?access_token=abc
	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *resterr.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	fmt.Printf("response %s", response)
	fmt.Println(response.StatusCode)
	if response == nil || response.Response == nil {
		return nil, resterr.NewInternalServerError("invalid restclient response when trying to login user")
	}
	if response.StatusCode > 299 {
		fmt.Println(response.String())
		var reserr resterr.RestErr
		err := json.Unmarshal(response.Bytes(), &reserr)
		if err != nil {
			return nil, resterr.NewInternalServerError("invalid error interface when trying to login user")
		}
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, resterr.NewInternalServerError("error when trying to unmarshal users response")
	}
	return &at, nil
}
