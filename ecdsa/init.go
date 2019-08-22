package ecdsa

import (
	"github.com/atlaslee/crypto"
)

const (
	CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160 = iota
)

const (
	LENOF_ADDRESS = 20
	LENOF_BIGINT  = 32
	LENOF_HASH    = 32
)

func init() {
	crypto.Regist(CRYPTOTYPEOF_ECDSA256_SHA256_RIPEMD160, &ECDSAUtils{})
}
