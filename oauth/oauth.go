package oauth

import (
	"bookstore_oauth-go/oauth/errors"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mercadolibre/golang-restlient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"
	paramAccesToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8000",
		Timeout: 200 * time.Microsecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

// IsPublic checks if the incoming request is public or not
func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}
	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(req.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

// AuthenticateRequest authenticates the requests
func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}

	cleanRequest(req)

	// http://api.bookstore.com/resource?access_token=abc123
	accessToken := req.URL.Query().Get(paramAccesToken)
	if accessToken == "" {
		return nil
	}

	at, err := getAccessToken(accessToken)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	req.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	req.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}

	req.Header.Del(headerXClientID)
	req.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	resp := oauthRestClient.Get("/oauth/access_token/%s", accessTokenID)

	if resp == nil || resp.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get access token")
	}

	if resp.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(resp.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(resp.bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error while trying to unmarshal access token")
	}
	return &at, nil
}
