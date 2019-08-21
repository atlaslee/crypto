package ecdsa

import (
	"bytes"
	"testing"
)

type S struct {
	Word string
}

func TestSignatureSetString(t *testing.T) {
	s := &S{"hello world"}
	prik := &PrivateKey{}
	prik.Random()
	sign1 := prik.Sign(s)
	str := sign1.String()
	t.Log("Signature1", str)

	sign2 := &Signature{}
	err := sign2.SetString(str)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Signature2", sign2.String())
	if bytes.Compare(sign1.Data(), sign2.Data()) != 0 {
		t.FailNow()
	}
}
