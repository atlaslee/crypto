package ecdsa

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/crypto/ripemd160"
	"whaleroc/crypto"
)

func Ripemd160Encrypt(bytes []byte) []byte {
	h := ripemd160.New()
	h.Reset()
	h.Write(bytes)
	return h.Sum(nil)
}

func Sha256Encrypt(bytes []byte) []byte {
	h := sha256.New()
	h.Reset()
	h.Write(bytes)
	return h.Sum(nil)
}

func Base64Encode(bytes []byte) string {
	return base64.URLEncoding.EncodeToString(bytes)
}

func Base64Decode(str string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(str)
}

type ECDSAUtils struct{}

func (this *ECDSAUtils) AddressFromBytes(bytes []byte) (address crypto.Address) {
	address = &Address{}
	address.SetData(bytes)
	return
}

func (this *ECDSAUtils) PrivateKeyFromBytes(bytes []byte) (privateKey crypto.PrivateKey) {
	privateKey = &PrivateKey{}
	privateKey.SetData(bytes)
	return
}

func (this *ECDSAUtils) PrivateKeyNew() crypto.PrivateKey {
	return &PrivateKey{}
}

func (this *ECDSAUtils) PublicKeyFromBytes(bytes []byte) (publicKey crypto.PublicKey) {
	publicKey = &PublicKey{}
	publicKey.SetData(bytes)
	return
}

func (this *ECDSAUtils) SignatureFromBytes(bytes []byte) (signature crypto.Signature) {
	signature = &Signature{}
	signature.SetData(bytes)
	return
}
