/*

Chapter-2: Fundamentals of Cryptography
Hands-On Web Authentication by Sambit Kumar Dash

This sample code takes an input of a password and generates a binhex encoding 
of a randomized string using the pbkdf2 function. 

Launch the application with the command: 
go run ./pbkdf.go password

It produces the result: 1e69ed9b36e1a4231bb8d273090790d510f1404e

*/
package main

import (
	"crypto/sha1"
	"encoding/hex"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	dk := pbkdf2.Key([]byte(os.Args[1]), []byte("12345678"), 4096, 20, sha1.New)
	encodedString := hex.EncodeToString(dk)
	println(encodedString)
}
