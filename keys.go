package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func generateKeysToFile(filename string) {
	defer func() {
		if recover() != nil {
			log.Fatal("program exited with error")
		}
	}()

	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	log.Println("Generated private key:", base64.StdEncoding.EncodeToString(pri))

	pubSsh, err := ssh.NewPublicKey(pub)
	if err != nil {
		log.Panic(err)
	}
	log.Println("Generated public key:", base64.StdEncoding.EncodeToString(pubSsh.Marshal()))

	priPem, err := ssh.MarshalPrivateKey(pri, "")
	if err != nil {
		log.Panic(err)
	}

	priBytes := pem.EncodeToMemory(priPem)

	func() {
		priFile, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
		}
		defer priFile.Close()
		_, err = priFile.Write(priBytes)
		if err != nil {
			log.Panic(err)
		}
		log.Println("Wrote private key to id_ed25519")
	}()

	pubBytes := ssh.MarshalAuthorizedKey(pubSsh)

	func() {
		pubFile, err := os.OpenFile(filename+".pub", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			log.Panic(err)
		}
		defer pubFile.Close()
		_, err = pubFile.Write(pubBytes)
		if err != nil {
			log.Panic(err)
		}
		log.Println("Wrote public key to id_ed25519.pub")
	}()
}
