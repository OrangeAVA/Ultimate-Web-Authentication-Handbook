/*

Chapter-1: Introduction to Web Authentication
Hands-On Web Authentication by Sambit Kumar Dash

This sample code helps you understand HTTP handlers and simple authentication methods. 

Launch the application with the command: 
go run ./main.go

The website runs at http://localhost:8080.

The website exposes the following endpoints:

/hello - it responds with a "Hello, World" message to the screen.
/count - it shows the importance of cookies. Every time you visit this endpoint, it 
     reports how many times you visited the URL.
/session - implements the counter using a session cookie. The session cookie makes 
     the counter transparent to the client. 
/basicauth - implements the basic authentication scheme of HTTP. You can use jdoe as 
     the username and password as the password to authenticate. 
/resource - when you try to access this URL, it redirects to the /login URL and 
     presents a form. You can provide jdoe as the username and password as the password 
     to authenticate. The scheme utilizes the session cookie to maintain 
     post-authentication sessions.
*/


package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	uuid "github.com/google/uuid"
)

func addHelloHandler() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, World!\n")
	})
}

func addCountHandler() {
	http.HandleFunc("/count", func(w http.ResponseWriter, req *http.Request) {
		count := 0
		if c, err := req.Cookie("count"); err == nil {
			if count, err = strconv.Atoi(c.Value); err != nil {
				log.Default().Print(err)
				count = 0
			}
		}
		count += 1

		http.SetCookie(w, &http.Cookie{
			Name:  "count",
			Value: strconv.Itoa(count),
		})

		str := fmt.Sprintf("You have visited: %d times.", count)
		log.Default().Print(str)

		io.WriteString(w, str)
	})
}

func addSessionHandler() {
	cmap := map[string]int{}
	http.HandleFunc("/session", func(w http.ResponseWriter, req *http.Request) {
		uid := ""
		if cookie, err := req.Cookie("session"); err != nil {
			uid = uuid.NewString()
			log.Default().Printf("No session found. Creating a new session: %s", uid)
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: uid,
			})
			cmap[uid] = 0
		} else {
			uid = cookie.Value
		}

		cmap[uid] += 1

		str := fmt.Sprintf("You have visited: %d times.", cmap[uid])
		log.Default().Print(str)

		io.WriteString(w, str)
	})
}

func addBasicAuthHandler() {
	pmap := map[string]string{"jdoe": "password"}
	http.HandleFunc("/basicauth", func(w http.ResponseWriter, req *http.Request) {
		if u, p, ok := req.BasicAuth(); ok {
			if pmap[u] == p {
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

func addFormBasedAuthHandler() {
	smap := map[string]string{}
	pmap := map[string]string{"jdoe": "password"}

	http.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
		form := `<form method="GET" enctype="application/x-www-form-urlencoded">
              <label for="user">Username:</label><br>
              <input type="text" id="user" name="user"><br>
              <label for="password">Password:</label><br>
              <input type="text" id="password" name="password">
              <input type="submit" value="Submit">
            </form>`
		user := req.FormValue("user")
		pass := req.FormValue("password")
		if user == "" || pass == "" {
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(form))
		} else {
			if pmap[user] == pass {
				str := fmt.Sprintf("User %s authenticated.", user)
				log.Default().Print(str)
				uid := uuid.NewString()
				log.Default().Printf("No session found. Creating a new session: %s", uid)
				http.SetCookie(w, &http.Cookie{
					Name:  "session",
					Value: uid,
				})
				smap[uid] = user
				w.Header().Add("Location", "/resource")
				w.WriteHeader(http.StatusFound)
			} else {
				str := fmt.Sprintf("User %s failed to authenticate.", user)
				log.Default().Print(str)
				w.Header().Add("Content-Type", "text/html")
				w.Write([]byte(form))
			}
		}
	})

	http.HandleFunc("/resource", func(w http.ResponseWriter, req *http.Request) {
		if cookie, err := req.Cookie("session"); err != nil {
			w.Header().Add("Location", "/login")
			w.WriteHeader(http.StatusFound)
		} else {
			uid := cookie.Value
			user := smap[uid]
			if user != "" {
				str := fmt.Sprintf("User %s authenticated.", user)
				log.Default().Printf("Session %s found. Allowing user %s to access", uid, user)
				io.WriteString(w, str)
			} else {
				w.Header().Add("Location", "/login")
				w.WriteHeader(http.StatusFound)
			}
		}
	})
}

func main() {
	addHelloHandler()
	addCountHandler()
	addSessionHandler()
	addBasicAuthHandler()
	addFormBasedAuthHandler()

	log.Fatal(http.ListenAndServe(":8080", nil))
}
