package handler

import (
	"log"
	"net/http"
	"openid/provider"
)

func NewHandler(google *provider.Google, salesforce *provider.Salesforce) {
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("hello"))
	})
	http.HandleFunc("/google/login", google.Request)
	http.HandleFunc("/google/callback", google.Callback)
	http.HandleFunc("/salesforce/login", salesforce.Request)
	http.HandleFunc("/salesforce/callback", salesforce.Callback)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
