/*
Chapter-7: Advanced Trends in Authentication
Hands-On Web Authentication by Sambit Kumar Dash

This sample code shows the matching of two face images.

Go to the folder frontend and build the flutter application using
flutter build web

You should use this code with a Linux environment or WSL 2 on a Windows system.

Start the server with the command: go run ./face.go

The website runs at http://localhost:8080/

The website will ask for your permission to access the camera.
*/

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	face "github.com/Kagami/go-face"
	git "github.com/go-git/go-git/v5"
)

func main() {
	const testpath = "testdata"

	modelspath := filepath.Join(testpath, "models")

	log.Println("Downloading face data... It may take several minutes.")
	os.Mkdir(testpath, 0750)

	git.PlainClone(testpath, false, &git.CloneOptions{
		URL: "https://github.com/Kagami/go-face-testdata",
	})

	log.Println("Face data downloaded.")

	rec, err := face.NewRecognizer(modelspath)
	if err != nil {
		log.Fatalf("Can't init face recognizer: %v", err)
	}
	defer rec.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.FileServer(http.Dir("frontend/build/web")).ServeHTTP(w, r)
	})

	http.HandleFunc("/compare", func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() == nil {
			img1 := r.Form.Get("img1")
			img2 := r.Form.Get("img2")
			imgbuf1, _ := base64.URLEncoding.DecodeString(img1)
			imgbuf2, _ := base64.URLEncoding.DecodeString(img2)
			face1, _ := rec.RecognizeSingleCNN(imgbuf1)
			face2, _ := rec.RecognizeSingleCNN(imgbuf2)
			dist := face.SquaredEuclideanDistance(face1.Descriptor, face2.Descriptor)
			msg := fmt.Sprintf("The square euclidean distance is: %f", dist)
			log.Println(msg)
			w.Write([]byte(msg))
		} else {
			msg := "Internal server error"
			log.Println(msg)
			http.Error(w, msg, http.StatusInternalServerError)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
