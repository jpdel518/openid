package model

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type JWT struct {
	Header          map[string]interface{} `json:"header"`
	Payload         map[string]interface{} `json:"payload"`
	Signature       []byte                 `json:"signature"`
	SignatureOrigin string                 `json:"signature_origin"`
}

// DecodeJWT decodes base64 encoded header.payload.signature
func DecodeJWT(idToken string) (*JWT, error) {
	data := strings.Split(idToken, ".")
	header := data[0]
	payload := data[1]
	signature := data[2]

	byteHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("decode header error: %v", err)
	}
	bytePayload, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload error: %v", err)
	}
	byteSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature error: %v", err)
	}

	jwt := &JWT{
		Signature:       byteSignature,
		SignatureOrigin: fmt.Sprintf("%s.%s", header, payload),
	}

	err = json.NewDecoder(strings.NewReader(string(byteHeader))).Decode(&jwt.Header)
	if err != nil {
		return nil, fmt.Errorf("decode byte header error: %v", err)
	}
	err = json.NewDecoder(strings.NewReader(string(bytePayload))).Decode(&jwt.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode byte payload error: %v", err)
	}

	return jwt, nil
}

func (j *JWT) Verify(clientId string, domain string) error {
	// signatureの検証
	err := j.verifySignature()
	if err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	}

	// audの検証
	err = j.verifyAud(clientId)
	if err != nil {
		return fmt.Errorf("failed to verify aud: %v", err)
	}

	// issの検証
	err = j.verifyIss(domain)
	if err != nil {
		return fmt.Errorf("failed to verify iss: %v", err)
	}

	// expの検証（有効期限切れ検証）
	err = j.verifyExp()
	if err != nil {
		return fmt.Errorf("failed to verify exp: %v", err)
	}

	return nil
}

// VerifySignature verifies JWT signature
func (j *JWT) verifySignature() error {
	pubKey := rsa.PublicKey{}
	var keyList map[string]interface{}

	// Googleの公開鍵を取得
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/certs", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request: %v", err)
	}
	err = json.NewDecoder(res.Body).Decode(&keyList)
	if err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}
	log.Printf("keyList: %v", keyList)

	// jwtのヘッダーからkidを取得
	kid := j.Header["kid"].(string)
	// kidに対応する公開鍵を取得
	for _, k := range keyList["keys"].([]interface{}) {
		key := k.(map[string]interface{})
		if (key["kid"]).(string) == kid {
			// nパラメータ、eパラメータを利用して公開鍵を生成
			// exponentは一般的に65537が使われているはず
			decodedE, err := base64.RawURLEncoding.DecodeString(key["e"].(string))
			if err != nil {
				return err
			}
			// modulusは公開鍵の長さを表す
			decodedN, err := base64.RawURLEncoding.DecodeString(key["n"].(string))
			if err != nil {
				return err
			}
			pubKey.E = int(new(big.Int).SetBytes(decodedE).Uint64())
			pubKey.N = new(big.Int).SetBytes(decodedN)
			break
		}
	}
	log.Printf("pubKey E: %v", pubKey.E)
	log.Printf("pubKey N: %v", pubKey.N)

	// 公開鍵で署名を検証
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(j.SignatureOrigin))
	err = rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, hasher.Sum(nil), j.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %v", err)
	} else {
		return nil
	}
}

// verifyAud verifies JWT aud
func (j *JWT) verifyAud(clientId string) error {
	// audの検証
	aud := j.Payload["aud"].(string)
	if aud != clientId {
		return fmt.Errorf("invalid aud: %v", aud)
	}
	return nil
}

// verifyIss verifies JWT iss
func (j *JWT) verifyIss(domain string) error {
	// issの検証
	iss := j.Payload["iss"].(string)
	if iss != domain {
		return fmt.Errorf("invalid iss: %v", iss)
	}
	return nil
}

// verifyExp verifies JWT exp
func (j *JWT) verifyExp() error {
	// expの検証
	exp := j.Payload["exp"].(float64)
	if exp < float64(time.Now().Unix()) {
		return fmt.Errorf("invalid exp: %v", exp)
	}
	return nil
}
