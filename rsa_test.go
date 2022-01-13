package xcrypto_test

import (
	xbase64 "github.com/goclub/base64"
	xcrypto "github.com/goclub/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var testPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDHc+PP8LuTlBL1zCX+lh9kcur
gHHIXFnV/tDK789DaJuhwZvQ1lu5Zdcn+ULbNUKkB6b5tCP0sZxlpoCVKMyKHtde
h/YGXwBD8sMc+XcRs0eh3/tyr4EoBu3bomzHWDGmHjH/F5GotFTrGcB6xQwAROy4
mT5SketlQ3c7tucI+QIDAQAB
-----END PUBLIC KEY-----
不要将这个测试的公钥用到你的项目中
`)
var testPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMMdz48/wu5OUEvX
MJf6WH2Ry6uAcchcWdX+0Mrvz0Nom6HBm9DWW7ll1yf5Qts1QqQHpvm0I/SxnGWm
gJUozIoe116H9gZfAEPywxz5dxGzR6Hf+3KvgSgG7duibMdYMaYeMf8Xkai0VOsZ
wHrFDABE7LiZPlKR62VDdzu25wj5AgMBAAECgYBKcdxYrp5EaHLwjNlIk0ciGfeY
pvhC1yGbqY6mb1soQAhpbkJyKudyVG4EHXGpy6dyiEzoJxg063NdwWp7/sYTHk/N
13UzGTudIKuNacnJk0WKu4owQticC71ZIqUjSZgN0CiEKQ6YfoGOFTzeMqzVYQjI
mPzGdLK74y3YYlmigQJBAObzhzYlWjOypx3klmrPTu2KXPg3ATTEB8kN/isY8bYu
ikVdd2yUd0AvaC7PPwEEjGmsSrEeXw1tsVfZ8VkBaikCQQDYR0+8VzGLdgIFQc/6
+IY5fQlEt/Hc7qsi7JT4o+f+BGJlAT7+OeDMThavKdWq1UvZDyCKdtYRfxQ1jj7D
4yJRAkBrG6InkGcm9sHecTb5Ti+ypqq7Svc6O3fI3L51ylm/PhJOXSyXpLsxf0r3
+pGjrTJZh9gUEJvQpIDM13zA5JERAkBI2zTsED9baIRjuvjR5Xhp00oVARYTw76Y
xDOm0qgq9NUki1fqEhs9F60ikqgspS+oziS7IC8as8FeDS3tlQ0RAkA5OdDvhQRQ
PI75ULyHazTEm4Rak8TKmKl64pmnwcw4GS9fKWs7jRAuem1OtwA8HAqjaDeXC8Cd
6fDfq7z5bZnE
-----END PRIVATE KEY-----
不要将这个测试的私钥用到你的项目中
`)
func TestPKIXPublicKey(t *testing.T) {
	// 使用公钥加密
	publicKey, err := xcrypto.NewPKIXPublicKey(testPublicKey) ; assert.NoError(t, err)
	ciphertext, err := publicKey.RsaEncryptPKCS1v15([]byte(`goclub`)) ; assert.NoError(t, err)
	cipherBase64 := xbase64.RawStdEncode(ciphertext)

	// 使用私钥解密
	privateKey, err := xcrypto.NewPKCS8PrivateKey(testPrivateKey) ; assert.NoError(t, err)
	ciphertextBase64v2, err  := xbase64.RawStdDecode(cipherBase64) ; assert.NoError(t, err)
	source, err := privateKey.RsaDecryptPKCS1v15(ciphertextBase64v2)  ; assert.NoError(t, err)
	 assert.Equal(t,string(source), "goclub")
}
