package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

func main() {
	var path string
	fmt.Print("Enter Your Secret Path: ")
	_, err1 := fmt.Scanf("%s", &path)
	if err1 != nil {
		fmt.Println("Error reading input path:", err1)
	}

	var myKeyFile string = path + "/key.txt"
	var myPlaintextFile string = path + "/plaintext.txt"
	var myEncodedFile string = path + "/ciphertext.bin"

	if _, err := os.Stat(myPlaintextFile); err == nil {
		fmt.Println("Encoding Starts:")
		encryptFile(myKeyFile, myPlaintextFile, myEncodedFile)
	} else {
		fmt.Println("Decoding Starts:")
		decryptFile(myKeyFile, myPlaintextFile, myEncodedFile)
	}
}

func encryptFile(myKeyFile string, myPlaintextFile string, myEncodedFile string) {
	createAesKey(myKeyFile)
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
		fmt.Println("Encoded File Generated : " + myEncodedFile)
		os.Remove(myPlaintextFile)
		os.Remove(myKeyFile)
	}

}

func decryptFile(myKeyFile string, myPlaintextFile string, myEncodedFile string) {
	createAesKey(myKeyFile)
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
		fmt.Println("Plaintext File Generated : " + myPlaintextFile)
		os.Remove(myEncodedFile)
		os.Remove(myKeyFile)
	}

}

func createAesKey(myKeyFile string) {

	var strInput string
	var passInput string
	fmt.Print("Enter your Name: ")
	_, err := fmt.Scanf("%s", &strInput)
	if err != nil {
		fmt.Println("Error reading input:", err)
	}

	fmt.Print("Enter your Password: ")
	_, err1 := fmt.Scanf("%s", &passInput)
	if err1 != nil {
		fmt.Println("Error reading input:", err1)
	}
	hexPassInput := hex.EncodeToString([]byte(passInput))

	mycmd := "openssl enc -aes-128-cbc -k " + strInput + " -S " + hexPassInput + " -P -md sha256 | awk '/key=/{print $1}'|cut -d'=' -f2|tr -d '\n'"
	out, _ := exec.Command("bash", "-c", mycmd).Output()

	err = ioutil.WriteFile(myKeyFile, out, 0777)
	if err != nil {
		log.Fatalf("write file err: %v", err.Error())
	}
}
