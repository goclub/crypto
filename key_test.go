package xcrypto_test

import (
	xbase64 "github.com/goclub/base64"
	xcrypto "github.com/goclub/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIyMlgkR8yNKiRoOJsXgJ0hdjg
uh49Sb9e6H5qqmuF+w/2R+G2YmHTMzEFCw5hSV6ptEjh7Niscr6V0Ol7vZOf6Lyx
U1v3cJkyiBcddm9c1+Hiu5hw/3j9s7YxGqpG25rws/VqDiof8DaZbAVNWjqTfRp8
WrlzAHAk+NKOuenxywIDAQAB
-----END PUBLIC KEY-----
不要将这个测试的公钥用到你的项目中
`)
var testPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMjIyWCRHzI0qJGg
4mxeAnSF2OC6Hj1Jv17ofmqqa4X7D/ZH4bZiYdMzMQULDmFJXqm0SOHs2KxyvpXQ
6Xu9k5/ovLFTW/dwmTKIFx12b1zX4eK7mHD/eP2ztjEaqkbbmvCz9WoOKh/wNpls
BU1aOpN9GnxauXMAcCT40o656fHLAgMBAAECgYBEArcrrZyKjgm3Ym6v1Fwyig//
dyu9CNj41fnUOau4M2Whv5F2DPcj6ggltCwHyil1hGrXlDmEmE10Q9KCpqF1BHDv
bwf7OjU4JRwo4UJHg+0Ugna4VEp3luLpl6CXwMkqP0FIpg55/2l0nqllGLoYML1H
ubMCNKyQFt0G0QQoUQJBAOSNM79Y69eh5r1Jsx/JMMynwCLTJiGK5e4qMN/FL8jV
moEk/b/N89OQ8HizoVi9TOdbPchFzLDzhZad+AucfxkCQQDg5eIF0SGw1Qqzlbor
h2g6LcGYKxmLURjOM6AR0MoRx7BZ6ch9SFM085H0RqldEx/IEUcvz0XcLjUWeR2g
4SiDAkBVaoQ1dhkmTKa8hYfBUGLBicwf98Pfc1a9bN05NCvIpjQJIfcHsQP4RMnq
gk/Bp3XPXWU4rQVz+H8rrDwgsss5AkEA1FMUZauApEMuHEgCgLARDcQ/Htup/Sau
RZbly4wUCl89tlWKDAWpULeYF0hTA2VXvvnY/GEysmIJitMDzuxj4wJBAKTg3s0Z
h8QGCUV7nEj+UB42yHNFrX5mu7KJbwXAWO4k9aQ3uXE8QVudW/9eCV0FHaXof/NN
2+kO01stA1p1yAY=
-----END PRIVATE KEY-----
不要将这个测试的私钥用到你的项目中
`)
func TestPKIXPublicKey(t *testing.T) {
	testEncryptoDecrypto(t, testPublicKey, testPrivateKey)
}
func testEncryptoDecrypto(t *testing.T, publicKeyBytes []byte, privateKeyBytes []byte) {
	// 使用公钥加密
	publicKey, err := xcrypto.ParsePKIXPublicKey(publicKeyBytes) ; assert.NoError(t, err)
	ciphertext, err := publicKey.RsaEncryptPKCS1v15([]byte(`goclub`)) ; assert.NoError(t, err)
	cipherBase64 := xbase64.EncodeRawStd(ciphertext)

	// 使用私钥解密
	privateKey, err := xcrypto.ParsePKCS8PrivateKey(privateKeyBytes) ; assert.NoError(t, err)

	assert.Equal(t,privateKey.PrivateKey.PublicKey , *publicKey.PublicKey)

	ciphertextBase64v2, err  := xbase64.DecodeRawStd(cipherBase64) ; assert.NoError(t, err)
	source, err := privateKey.RsaDecryptPKCS1v15(ciphertextBase64v2)  ; assert.NoError(t, err)
	assert.Equal(t,string(source), "goclub")
}

func TestGenRsaKeyPKCS8(t *testing.T) {
	rsaKey, err := xcrypto.GenRsaKeyPKCS8(1024) ; assert.NoError(t, err)
	testEncryptoDecrypto(t, rsaKey.PublicKeyBytes, rsaKey.PrivateKeyBytes, )
}

