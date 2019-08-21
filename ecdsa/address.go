package ecdsa

import (
	"bytes"
	"whaleroc"
	"whaleroc/crypto"
)

const (
	SIZEOF_ADDRESS = 1 + LENOF_ADDRESS
)

type Address struct {
	crypto byte
	data   []byte
}

func (this *Address) Crypto() byte {
	return this.crypto
}

func (this *Address) Data() []byte {
	return this.data
}

func (this *Address) SetData(data []byte) (err error) {
	if len(data) != LENOF_ADDRESS {
		return whaleroc.ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160
	this.data = data
	return
}

func (this *Address) String() string {
	return Base64Encode(this.data)
}

func (this *Address) SetString(str string) (err error) {
	data, err := Base64Decode(str)
	if err != nil {
		return
	}

	this.SetData(data)
	return
}

func (this *Address) Validate(publicKey crypto.PublicKey) bool {
	return bytes.Compare(publicKey.Address().Data(), this.data) == 0
}

func (this *Address) Bytes() (b []byte) {
	b = make([]byte, len(this.data)+1)
	b[0] = this.crypto

	copy(b[1:], this.data)
	return
}

func (this *Address) SetBytes(bytes []byte) error {
	if len(bytes) != SIZEOF_ADDRESS {
		return whaleroc.ERR_SIZEOF_BYTES_INCORRECT
	}

	this.crypto = bytes[0]
	this.SetData(bytes[1:])
	return nil
}
