package xcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	xerr "github.com/goclub/error"
)

type PKIXPublicKey struct {
	PublicKey *rsa.PublicKey
}
func ParsePKIXPublicKey(publicKey []byte) (public PKIXPublicKey, err error) {
	block, rest := pem.Decode(publicKey)
	_ = rest
	if block == nil || block.Type != "PUBLIC KEY" {
		err = xerr.New("NewRSAPublic(publicKey) publicKey is not PUBLIC KEY")
		return
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes) ; if err != nil {
		return
	}
	public = PKIXPublicKey{
		PublicKey: pub.(*rsa.PublicKey),
	}
	return
}
func (r PKIXPublicKey) RsaEncryptPKCS1v15(source []byte) (ciphertext []byte, err error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.PublicKey, source)
}
type PKCS8PrivateKey struct {
	PrivateKey *rsa.PrivateKey
}
func ParsePKCS8PrivateKey(privateKey []byte) (private PKCS8PrivateKey, err error) {
	block, rest := pem.Decode(privateKey)
	_ = rest
	if block == nil || block.Type != "PRIVATE KEY" {
		err = xerr.New("NewPKCS8PrivateKey(privateKey) privateKey is not PRIVATE KEY")
		return
	}
	pri, err := x509.ParsePKCS8PrivateKey(block.Bytes) ; if err != nil {
		return
	}
	private = PKCS8PrivateKey{
		PrivateKey: pri.(*rsa.PrivateKey),
	}
	return
}

func (r PKCS8PrivateKey) RsaDecryptPKCS1v15(ciphertext []byte) (source []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, r.PrivateKey, ciphertext)
}

type RsaKeyPKCS8 struct {
	PrivateKeyBytes []byte
	PublicKeyBytes []byte
}
// GenRsaKey(1024)
func GenRsaKeyPKCS8(keySize uint) (rsaKey RsaKeyPKCS8, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, int(keySize)) ; if err != nil {
		return
	}
	// 创建私钥
	privateDerText, err := x509.MarshalPKCS8PrivateKey(privateKey) ; if err != nil {
		return
	}
	privateBlock := pem.Block{
		Type : "PRIVATE KEY",
		Bytes: privateDerText,
	}
	rsaKey.PrivateKeyBytes = pem.EncodeToMemory(&privateBlock)
	// 创建公钥
	publicKey := privateKey.PublicKey
	publicDerText,err := x509.MarshalPKIXPublicKey(&publicKey) ; if err != nil {
		return
	}
	publicBlock := pem.Block{
		Type : "PUBLIC KEY",
		Bytes: publicDerText,
	}
	rsaKey.PublicKeyBytes = pem.EncodeToMemory(&publicBlock)
	return
}
