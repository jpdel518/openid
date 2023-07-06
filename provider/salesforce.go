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

var _ IDProvider = (*Salesforce)(nil)

type Salesforce struct {
	responseType string
	clientId     string
	clientSecret string
	redirectUri  string
	state        string
	scope        string
}

func NewSalesforceProvider() *Salesforce {
	return &Salesforce{
		responseType: os.Getenv("SALESFORCE_RESPONSE_TYPE"),
		clientId:     os.Getenv("SALESFORCE_CLIENT_ID"),
		clientSecret: os.Getenv("SALESFORCE_CLIENT_SECRET"),
		redirectUri:  os.Getenv("SALESFORCE_REDIRECT_URI"),
		state:        os.Getenv("SALESFORCE_STATE"),
		scope:        os.Getenv("SALESFORCE_SCOPE"),
	}
}

func (s *Salesforce) Request(writer http.ResponseWriter, request *http.Request) {
	nonce := utils.RandomString(32)

	v := url.Values{}
	v.Add("response_type", s.responseType)
	v.Add("client_id", s.clientId)
	v.Add("redirect_uri", s.redirectUri)
	v.Add("nonce", nonce)
	v.Add("state", s.state)
	v.Add("scope", s.scope)

	uri := "https://jcg4-dev-ed.develop.my.salesforce.com/services/oauth2/authorize?" + v.Encode()
	log.Printf("redirect to %s", uri)
	http.Redirect(writer, request, uri, http.StatusFound)
}

func (s *Salesforce) Callback(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	code := query.Get("code")
	state := query.Get("state")
	if state != s.state {
		log.Printf("invalid state: %s", state)
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte("invalid state"))
		return
	}
	log.Printf("code: %s", code)

	// tokenのrequest
	token, err := s.requestToken(code)
	if err != nil {
		log.Printf("failed to request token: %s", err)
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
	// err = jwt.Verify(s.clientId, "https://jcg4-dev-ed.develop.my.salesforce.com")
	// if err != nil {
	// 	log.Printf("failed to verify jwt: %v", err)
	// 	// writer.WriteHeader(http.StatusInternalServerError)
	// 	// _, _ = writer.Write([]byte("failed to verify jwt"))
	// 	// return
	// }

	// openidで取得したuser情報を表示
	log.Printf("jwt: %v", jwt)

	// アクセストークンを使用してUserInfo APIを叩く
	// 会社名、部署、役職等は接続アプリケーションのカスタム属性で追加。カスタム属性はresponseのprofile.custom_attributesに入る。
	profile, err := s.GetUserInfo(token["access_token"].(string))
	log.Printf("profile: %v", profile)

	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(fmt.Sprintf("hello %s", jwt.Payload["name"])))
}

func (s *Salesforce) requestToken(code string) (map[string]interface{}, error) {
	var token map[string]interface{}

	v := url.Values{}
	v.Add("grant_type", "authorization_code")
	v.Add("client_id", s.clientId)
	v.Add("client_secret", s.clientSecret)
	v.Add("redirect_uri", s.redirectUri)
	v.Add("code", code)

	req, err := http.NewRequest("POST", "https://jcg4-dev-ed.develop.my.salesforce.com/services/oauth2/token", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// req.Header.Add("Authorization", "Basic "+base64.URLEncoding.EncodeToString([]byte(s.clientId+":"+s.clientSecret)))
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	log.Printf("response status: %s", resp.Status)
	log.Printf("response header: %v", resp.Header)
	log.Printf("response body: %v", resp.Body)

	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to request token: %v", token)
	}

	return token, nil
}

func (s *Salesforce) GetUserInfo(token string) (map[string]interface{}, error) {
	var data map[string]interface{}

	request, err := http.NewRequest("GET", "https://jcg4-dev-ed.develop.my.salesforce.com/services/oauth2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Authorization", "Bearer "+token)
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
