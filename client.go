// +build ignore

package main

import (
	"io"
	"log"
	"os"

	"github.com/jlubawy/go-oauth2-example/config"

	"golang.org/x/net/context"
	_ "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)

	clientConfig := &clientcredentials.Config{
		// ClientID is the application's ID.
		ClientID: config.ClientID,

		// ClientSecret is the application's secret.
		ClientSecret: config.ClientSecret,

		// TokenURL is the resource server's token endpoint
		// URL. This is a constant specific to each server.
		TokenURL: config.TokenURL,

		// Scope specifies optional requested permissions.
		//Scopes []string

		// EndpointParams specifies additional parameters for requests to the token endpoint.
		//EndpointParams url.Values
	}

	client := clientConfig.Client(context.TODO())
	resp, err := client.Get("http://localhost:8080/resource/secret")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)

}
