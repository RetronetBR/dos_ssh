package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	mrand "math/rand"
	"os"
)

func LoadOrCreateHostKey(file string) []byte {
	privateBytes, err := os.ReadFile(file)
	if err == nil {
		return privateBytes
	}
	if !errors.Is(err, os.ErrNotExist) {
		log.Fatalln("Failed to load private key")
	}

	key, genErr := rsa.GenerateKey(crand.Reader, 2048)
	if genErr != nil {
		log.Fatalln("Failed to generate private key")
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	privateBytes = pem.EncodeToMemory(block)
	if writeErr := os.WriteFile(file, privateBytes, 0600); writeErr != nil {
		log.Fatalln("Failed to write private key")
	}
	return privateBytes
}

func MessageHub(Input chan []byte, Clients map[string]chan []byte) {

	for {
		inbound := <-Input
		SubscribersMu.RLock()
		subscribers := make([]chan []byte, 0, len(Clients))
		for _, v := range Clients {
			subscribers = append(subscribers, v)
		}
		SubscribersMu.RUnlock()
		for _, v := range subscribers {
			select {
			case v <- inbound:
			default:
				log.Println("MessageHub dropped framebuffer update for a slow subscriber")
			}
		}
	}

}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b)
}
