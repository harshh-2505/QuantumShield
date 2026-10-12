// Package legacy is a web parity fixture for the source scanner.
package legacy

import (
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
)

func Keys() {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kex, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, _, _ = rsaKey, ecKey, kex
}

func Hashes(b []byte) {
	h1 := md5.New()
	h2 := sha1.New()
	_, _ = h1, h2
}

func Ciphers(key []byte) {
	c1, _ := rc4.NewCipher(key)
	c2, _ := des.NewTripleDESCipher(key)
	_, _ = c1, c2
}

var Config = &tls.Config{
	MinVersion:       tls.VersionTLS10,
	CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
}
