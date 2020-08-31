package lkf

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

var c = new(Cryptor)
var data = make([]byte, 1024*32)

func TestDecrypt(t *testing.T) {
	c := new(Cryptor)
	data := make([]byte, 1024*32)
	const hash string = "93eee826bbbd10f3156445b5fa04bfcc2846dfdb8868bbaa52880ad566886b61"
	for k := 0; k < 1024; k++ {
		c.Decrypt(data)
	}
	sum := sha256.Sum256(data)
	if fmt.Sprintf("%x", sum) != hash {
		t.Error("Failed")
	}
}

func TestEncrypt(t *testing.T) {
	c := new(Cryptor)
	data := make([]byte, 1024*32)
	const hash string = "e76a64360daa47500a043cbc4d85848e6ade35f42fb72cf7bef4e567d772eef8"
	for k := 0; k < 1024; k++ {
		c.Encrypt(data)
	}
	sum := sha256.Sum256(data)
	if fmt.Sprintf("%x", sum) != hash {
		t.Error("Failed")
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := 0; k < 1024; k++ {
			c.Decrypt(data)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := 0; k < 1024; k++ {
			c.Encrypt(data)
		}
	}
}
