package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/atlaslee/crypto"
	"math/big"
)

const (
	LENOF_PRIVATEKEY  = LENOF_BIGINT
	SIZEOF_PRIVATEKEY = 1 + LENOF_PRIVATEKEY
)

type PrivateKey struct {
	crypto byte
	d      *big.Int
}

func (this *PrivateKey) Crypto() byte {
	return this.crypto
}

func (this *PrivateKey) Data() []byte {
	return this.d.Bytes()
}

func (this *PrivateKey) SetData(bytes []byte) error {
	if len(bytes) != LENOF_PRIVATEKEY {
		println("PrivateKey.SetData", Base64Encode(bytes))
		return crypto.ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160
	this.d = big.NewInt(0).SetBytes(bytes)
	return nil
}

func (this *PrivateKey) Mnemonics() (mnemonics []string) {
	return crypto.Bytes2Mnemonics(this.Data())
}

func (this *PrivateKey) String() string {
	return Base64Encode(this.Bytes())
}

func (this *PrivateKey) SetMnemonics(mnemonics []string) error {
	return this.SetData(crypto.Mnemonics2Bytes(mnemonics))
}

func (this *PrivateKey) SetString(str string) (err error) {
	bytes, err := Base64Decode(str)
	if err != nil {
		return
	}

	return this.SetBytes(bytes)
}

func (this *PrivateKey) Random() {
	random := make([]byte, LENOF_BIGINT)
	rand.Read(random)
	this.SetData(random)
}

func (this *PrivateKey) PrivateKey() *ecdsa.PrivateKey {
	publicKey, ok := this.PublicKey().(*PublicKey)
	if !ok {
		return nil
	}

	return &ecdsa.PrivateKey{*(publicKey.PublicKey()), this.d}
}

func (this *PrivateKey) PublicKey() crypto.PublicKey {
	x, y := elliptic.P256().ScalarBaseMult(this.Data())
	return &PublicKey{this.crypto, x, y}
}

func (this *PrivateKey) Sign(signable crypto.Signable) crypto.Signature {
	hash := Sha256Encrypt(signable.Abstract())
	r, s, err := ecdsa.Sign(rand.Reader, this.PrivateKey(), hash)
	if err != nil {
		return nil
	}

	publicKey, ok := this.PublicKey().(*PublicKey)
	if !ok {
		return nil
	}

	return &Signature{this.crypto, r, s, publicKey.X(), publicKey.Y(), hash}
}

func (this *PrivateKey) Bytes() (bytes []byte) {
	bytes = make([]byte, SIZEOF_PRIVATEKEY)
	bytes[0] = this.crypto
	copy(bytes[1:], this.Data())
	return
}

func (this *PrivateKey) SetBytes(bytes []byte) error {
	if len(bytes) != SIZEOF_PRIVATEKEY {
		return crypto.ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = bytes[0]
	this.SetData(bytes[1:])
	return nil
}
