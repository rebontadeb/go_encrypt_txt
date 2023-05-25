package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
	"os"
)

var myKeyFile string = "/Users/rebontadeb/Dropbox/DOCS/SECRETS/key.txt"
var myPlaintextFile string = "/Users/rebontadeb/Dropbox/DOCS/SECRETS/plaintext.txt"
var myEncodedFile string = "/Users/rebontadeb/Dropbox/DOCS/SECRETS/ciphertext.bin"

func main() {
	// encryptFile()
	decryptFile()
}

func encryptFile() {
	// Reading plaintext file
	plainText, err := ioutil.ReadFile(myPlaintextFile)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Reading key
	key, err := ioutil.ReadFile(myKeyFile)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cipher err here: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("nonce  err: %v", err.Error())
	}

	// Decrypt file
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Writing ciphertext file
	err = ioutil.WriteFile(myEncodedFile, cipherText, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	} else {
		os.Remove(myPlaintextFile)
	}

}

func decryptFile() {
	// Reading ciphertext file
	cipherText, err := ioutil.ReadFile(myEncodedFile)
	if err != nil {
		log.Fatal(err)
	}

	// Reading key
	key, err := ioutil.ReadFile(myKeyFile)
	if err != nil {
		log.Fatalf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("cipher GCM err: %v", err.Error())
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		log.Fatalf("decrypt file err: %v", err.Error())
	}

	// Writing decryption content
	err = ioutil.WriteFile(myPlaintextFile, plainText, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	} else {
		os.Remove(myEncodedFile)
	}

}
