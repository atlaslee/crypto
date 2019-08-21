package ecdsa

import (
	"bytes"
	"testing"
)

func TestAddressSetString(t *testing.T) {
	prik := &PrivateKey{}
	prik.Random()
	addr1 := prik.PublicKey().Address()
	str := addr1.String()
	t.Log("Address1", str)

	addr2 := &Address{}
	err := addr2.SetString(str)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Address2", addr2.String())
	if bytes.Compare(addr1.Data(), addr2.Data()) != 0 {
		t.FailNow()
	}
}
