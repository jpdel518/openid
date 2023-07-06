package provider

import "net/http"

type IDProvider interface {
	Request(writer http.ResponseWriter, request *http.Request)
	Callback(writer http.ResponseWriter, request *http.Request)
}
