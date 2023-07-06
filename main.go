package main

import (
	"openid/handler"
	"openid/provider"
	"openid/utils"
)

func init() {
	utils.LoadEnv()
}

func main() {
	google := provider.NewGoogleProvider()
	salesforce := provider.NewSalesforceProvider()
	handler.NewHandler(google, salesforce)
}
