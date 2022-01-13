# ctypto

[![Go Reference](https://pkg.go.dev/badge/github.com/goclub/crypto.svg)](https://pkg.go.dev/github.com/goclub/crypto)

## RSA

RSA非对称加密公私钥对生成，输出PEM格式的公私钥对，同时支持PKCS#1、PKCS#8密钥格式输出；生成的公私钥对，可拷贝到文本文件，保存为.key文件即可使用。

**PEM格式：**RSA公私钥对常用的编码方式，OPENSSL以PEM格式为主，相对DER可读性更强，以BASE64编码呈现；
开头类似 `-----BEGIN PRIVATE KEY-----`
结尾类似 `-----END PRIVATE KEY-----`

**PKCS#8**密钥格式，多用于JAVA、PHP程序加解密中，为目前用的比较多的密钥、证书格式；
**PKCS#1**密钥格式，多用于JS等其它程序加解密，属于比较老的格式标准。
**PKCS#1**和**PKCS#8**的主要区别，从本质上说，PKCS#8格式增加验证数据段，保证密钥正确性。

[示例](./example_test.go)