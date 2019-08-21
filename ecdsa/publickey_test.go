package ecdsa

import (
	"bytes"
	"testing"
)

func TestPublicKeySetString(t *testing.T) {
	prik := &PrivateKey{}
	prik.Random()
	pubk1 := prik.PublicKey()
	str := pubk1.String()
	t.Log("PublicKey1", str)

	pubk2 := &PublicKey{}
	err := pubk2.SetString(str)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("PublicKey2", pubk2.String())
	if bytes.Compare(pubk1.Data(), pubk2.Data()) != 0 {
		t.FailNow()
	}
}

func TestPublicKeyAddress(t *testing.T) {
	prik := &PrivateKey{}
	prik.Random()
	pubk := prik.PublicKey()
	addr := pubk.Address()
	t.Log("Address", addr.String())

	if !addr.Validate(pubk) {
		t.FailNow()
	}
}
