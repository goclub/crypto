package xcrypto_test

import (
	xbase64 "github.com/goclub/base64"
	xcrypto "github.com/goclub/crypto"
	xerr "github.com/goclub/error"
	"log"
	"testing"
)

func ExampleGenRsaKeyPKCS8() {
	var err error ; defer func() { if err != nil { xerr.PrintStack(err) } }()
	rsaKey, err := xcrypto.GenRsaKeyPKCS8(1024) ; if err != nil {
	    return
	}
	log.Print("rsaKey.PublicKeyBytes:\n", string(rsaKey.PublicKeyBytes))
	log.Print("rsaKey.PrivateKey:\n", string(rsaKey.PrivateKeyBytes))
	publicKey, err := xcrypto.ParsePKIXPublicKey(rsaKey.PublicKeyBytes) ; if err != nil {
	    return
	}
	cipherText, err := publicKey.RsaEncryptPKCS1v15([]byte("goclub.run")) ; if err != nil {
	    return
	}
	log.Print("base64(cipherText):\n", string(xbase64.EncodeRawStd(cipherText)))
	privateKey, err := xcrypto.ParsePKCS8PrivateKey(rsaKey.PrivateKeyBytes) ; if err != nil {
	    return
	}
	source, err := privateKey.RsaDecryptPKCS1v15(cipherText) ; if err != nil {
	    return
	}
	log.Print("source:\n", string(source)) // goclub.run
}
func TestExampleGenRsaKeyPKCS8(t *testing.T) {
	ExampleGenRsaKeyPKCS8()
}
