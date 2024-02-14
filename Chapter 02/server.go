/*

Chapter-2: Fundamentals of Cryptography
Ultimate Web Authentication Handbook by Sambit Kumar Dash

Start the server with the command: go run ./server.go
Access the website by typing the URL http://localhost:8080/basicauth
on the browser.
- The passwords are stored in the system in a password file as hashed keys.
- We use PBKDF2 to generate the keys and store them in the binhex format in
the password.json file.
- The user provides jdoe as the username and password as the password. We
generate the PBKDF2 of the password and compare it with the value stored in
the password.json file.
- On success, the browser shows the success message.
*/

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func addBasicAuthHandler() {
	var pmap map[string]string
	if jsonFile, err := os.Open("password.json"); err == nil {
		byteValue, _ := io.ReadAll(jsonFile)
		json.Unmarshal([]byte(byteValue), &pmap)
		log.Default().Print(pmap)
	} else {
		log.Fatal(err)
	}
	http.HandleFunc("/basicauth", func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); ok {
			dk := hex.EncodeToString(pbkdf2.Key([]byte(p), []byte("12345678"), 4096, 20, sha1.New))
			if pmap[u] == dk {
				str := fmt.Sprintf("User %s authenticated.", u)
				io.WriteString(w, str)
				log.Default().Print(str)
			} else {
				str := fmt.Sprintf("User %s failed to authenticate.", u)
				w.WriteHeader(http.StatusUnauthorized)
				log.Default().Print(str)
			}
		} else {
			w.Header().Add("WWW-Authenticate", "Basic Realm=\"Access Server\"")
			w.WriteHeader(http.StatusUnauthorized)
			log.Default().Print("Basic authentication needed.")
		}
	})
}

func main() {
	addBasicAuthHandler()
	log.Fatal(http.ListenAndServe(":8080", nil))
}
