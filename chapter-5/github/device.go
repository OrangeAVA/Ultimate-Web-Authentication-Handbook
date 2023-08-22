/*
Chapter-5: Federated Authentication-II
Hands-On Web Authentication by Sambit Kumar Dash

This sample code shows the device grant in OAuth 2.

You will require a GitHub account with OAuth authentication enabled and set
up the environment variables:

GH_CLIENT_ID: <<GitHub OAuth Client ID>>

Launch with the command: go run ./device.go

Follow the console for the next steps.
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

type DeviceAuthResponse struct {
	VerificationURI string
	DeviceCode      string
	UserCode        string
	ExpiresIn       time.Duration
	Interval        time.Duration
}

func get_device_authorization(device_uri string, client_id string, scope []string) (
	devres *DeviceAuthResponse, err error,
) {
	var res *http.Response
	if res, err = http.PostForm(device_uri, url.Values{
		"client_id": {client_id},
		"scope":     scope,
	}); err != nil {
		log.Fatal(err)
	} else {
		if res.StatusCode == 200 {
			defer res.Body.Close()
			var (
				b  []byte
				vs url.Values
			)
			if b, err = io.ReadAll(res.Body); err == nil {
				if vs, err = url.ParseQuery(string(b)); err == nil {
					interval, _ := strconv.ParseInt(vs["interval"][0], 10, 0)
					expires_in, _ := strconv.ParseInt(vs["expires_in"][0], 10, 0)
					devres = &DeviceAuthResponse{
						VerificationURI: vs["verification_uri"][0],
						DeviceCode:      vs["device_code"][0],
						UserCode:        vs["user_code"][0],
						ExpiresIn:       time.Duration(expires_in * int64(time.Second)),
						Interval:        time.Duration(interval * int64(time.Second)),
					}
				}
			}
		}
	}
	return
}

func poll_for_access_token(
	token_uri string,
	client_id string,
	devres *DeviceAuthResponse,
) (access_token string, err error) {
	var res *http.Response
	expire_time := time.Now().Add(devres.ExpiresIn)
	for {
		if res, err = http.PostForm(token_uri, url.Values{
			"client_id":   {client_id},
			"device_code": {devres.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}); err == nil {
			if res.StatusCode == 200 {
				defer res.Body.Close()
				var (
					b  []byte
					vs url.Values
				)
				if b, err = io.ReadAll(res.Body); err == nil {
					if vs, err = url.ParseQuery(string(b)); err == nil {
						if reason, ok := vs["error"]; !ok {
							access_token = vs["access_token"][0]
							break
						} else if reason[0] != "slow_down" {
							devres.Interval += (5 * time.Second)
						} else if reason[0] != "authorization_pending" {
							err = fmt.Errorf(vs["error_description"][0])
							break
						}
					}
				}
			}
		}
		log.Println("Waiting for user consent...")
		time.Sleep(devres.Interval)
		if time.Now().After(expire_time) {
			err = fmt.Errorf("User did not authorize.")
			break
		}
	}
	return
}

func get_device_flow_access_token(c map[string]string) (access_token string, err error) {
	var devres *DeviceAuthResponse
	if devres, err = get_device_authorization(c["device_uri"], c["client_id"], []string{c["scope"]}); err == nil {
		println("Using a browser on another device, visit: ")
		println(devres.VerificationURI)
		println("")
		println("And enter the code: ")
		println(devres.UserCode)

		access_token, err = poll_for_access_token(c["token_uri"], c["client_id"], devres)
	}
	return
}

func print_user_info(access_token string) (err error) {
	var (
		user_uri = "https://api.github.com/user"
		req      *http.Request
		res      *http.Response
	)
	if req, err = http.NewRequest("GET", user_uri, nil); err == nil {
		req.Header.Add("Accept", "application/vnd.github+json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", access_token))
		if res, err = http.DefaultClient.Do(req); err == nil {
			if res.StatusCode == 200 {
				defer res.Body.Close()
				b, _ := io.ReadAll(res.Body)
				var dst bytes.Buffer
				json.Indent(&dst, b, "", "  ")
				log.Print(dst.String())
			}
		}
	}
	return
}

func main() {
	client_id, ok := os.LookupEnv("GH_CLIENT_ID")
	if !ok {
		log.Panicf("Environment Variable GH_CLIENT_ID not found")
	}
	var (
		access_token string
		err          error
	)
	if access_token, err = get_device_flow_access_token(map[string]string{
		"client_id":  client_id,
		"device_uri": "https://github.com/login/device/code",
		"token_uri":  "https://github.com/login/oauth/access_token",
		"scope":      "user",
	}); err == nil {
		log.Println("Contacting the resource server for user info...")
		err = print_user_info(access_token)
	}
	if err != nil {
		log.Panic(err.Error())
	}
}
