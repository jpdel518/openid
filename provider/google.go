package provider

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"openid/model"
	"openid/utils"
	"os"
	"strings"
)

var _ IDProvider = (*Google)(nil)

type Google struct {
	responseType string
	scope        string
	clientId     string
	clientSecret string
	redirectUri  string
	state        string
}

func NewGoogleProvider() *Google {
	return &Google{
		responseType: os.Getenv("GOOGLE_RESPONSE_TYPE"),
		scope:        os.Getenv("GOOGLE_SCOPE"),
		clientId:     os.Getenv("GOOGLE_CLIENT_ID"),
		clientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		redirectUri:  os.Getenv("GOOGLE_REDIRECT_URI"),
		state:        os.Getenv("GOOGLE_STATE"),
	}
}

func (g *Google) Request(writer http.ResponseWriter, request *http.Request) {
	nonce := utils.RandomString(32)

	v := url.Values{}
	v.Add("response_type", g.responseType)
	v.Add("client_id", g.clientId)
	v.Add("redirect_uri", g.redirectUri)
	v.Add("nonce", nonce)
	v.Add("scope", g.scope)
	v.Add("state", g.state)
	v.Add("access_type", "offline")

	uri := fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?%s", v.Encode())
	log.Printf("redirect to %s", uri)
	http.Redirect(writer, request, uri, http.StatusFound)
}

func (g *Google) Callback(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	if state != g.state {
		log.Printf("invalid state: %s", state)
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("invalid state"))
		return
	}

	// tokenのrequest
	token, err := g.requestToken(code)
	if err != nil {
		log.Printf("failed to request token: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte("failed to request token"))
		return
	}
	log.Printf("token: %v", token)

	// id_tokenを取得し、base64 decode
	idToken := token["id_token"].(string)
	jwt, err := model.DecodeJWT(idToken)
	if err != nil {
		log.Printf("failed to decode jwt: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte("failed to decode jwt"))
		return
	}

	// id_tokenの検証（認証エンドポイントと直接やりとりしている場合は本来であれば検証を行う必要はない）
	err = jwt.Verify(os.Getenv("GOOGLE_CLIENT_ID"), "https://accounts.google.com")
	if err != nil {
		log.Printf("failed to verify jwt: %v", err)
		// writer.WriteHeader(http.StatusInternalServerError)
		// _, _ = writer.Write([]byte("failed to verify jwt"))
		// return
	}

	// openidで取得したuser情報を表示
	log.Printf("openid parameters: %v", jwt.Payload)

	// user情報を取得
	userInfo, err := g.getUserInfo(token["access_token"].(string))
	if err != nil {
		log.Printf("failed to get user info: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		_, _ = writer.Write([]byte("failed to get user info"))
		return
	}

	log.Printf("user info: %v", userInfo)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte("success to get user info"))
}

func (g *Google) requestToken(code string) (map[string]interface{}, error) {
	var token map[string]interface{}

	v := url.Values{}
	v.Add("code", code)
	v.Add("client_id", g.clientId)
	v.Add("client_secret", g.clientSecret)
	v.Add("redirect_uri", g.redirectUri)
	v.Add("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}

	res, err := client.Do(req)

	err = json.NewDecoder(res.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	log.Printf("token: %v", token)

	return token, nil
}

func (g *Google) getUserInfo(token string) (map[string]interface{}, error) {
	var data map[string]interface{}

	request, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	client := &http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(res.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
