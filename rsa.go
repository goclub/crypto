package xcrypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	xerr "github.com/goclub/error"
)

type PKIXPublicKey struct {
	publicKey *rsa.PublicKey
}
func NewPKIXPublicKey(publicKey []byte) (public PKIXPublicKey, err error) {
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
		publicKey: pub.(*rsa.PublicKey),
	}
	return
}
func (r PKIXPublicKey) RsaEncryptPKCS1v15(source []byte) (ciphertext []byte, err error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, source)
}
type PKCS8PrivateKey struct {
	privateKey *rsa.PrivateKey
}
func NewPKCS8PrivateKey(privateKey []byte) (private PKCS8PrivateKey, err error) {
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
		privateKey: pri.(*rsa.PrivateKey),
	}
	return
}

func (r PKCS8PrivateKey) RsaDecryptPKCS1v15(ciphertext []byte) (source []byte, err error) {
	return rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, ciphertext)
}