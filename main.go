package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/containers/ocicrypt/keywrap/keyprovider"
	"io"
	"log"
	"os"
)

var (
	key = []byte("passphrasewhichneedstobe32bytes!")
)

//Mock annotation packet, which goes into container image manifest
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

func main() {

	var input keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.NewDecoder(os.Stdin).Decode(&input)
	if err != nil {
		log.Fatal("decoding input", err)
	}

	if input.Operation == keyprovider.OpKeyWrap {
		b, err := WrapKey(input)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", b)
	} else if input.Operation == keyprovider.OpKeyUnwrap {

		b, err := UnwrapKey(input)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", b)
	} else {
		log.Fatalf("Operation %v not recognized", input.Operation)
	}

	return
}

func WrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)

	nonce := make([]byte, gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	wrappedKey := gcm.Seal(nonce, nonce, keyP.KeyWrapParams.OptsData, nil)

	jsonString, _ := json.Marshal(annotationPacket{
		KeyUrl:     "https://key-provider/key-uuid",
		WrappedKey: wrappedKey,
		WrapType:   "AES",
	})

	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{
			Annotation: jsonString,
		},
	})
}

func UnwrapKey(keyP keyprovider.KeyProviderKeyWrapProtocolInput) ([]byte, error) {
	apkt := annotationPacket{}
	err := json.Unmarshal(keyP.KeyUnwrapParams.Annotation, &apkt)
	if err != nil {
		return nil, err
	}
	ciphertext := apkt.WrappedKey

	c, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	unwrappedKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return json.Marshal(keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: unwrappedKey},
	})
}
