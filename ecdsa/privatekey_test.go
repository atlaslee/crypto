package ecdsa

import (
	"bytes"
	"testing"
)

func TestPrivateKeyRandom(t *testing.T) {
	pk := &PrivateKey{}
	pk.Random()
	t.Log("PrivateKey", pk.String())

	data := pk.Data()
	if len(data) != LENOF_PRIVATEKEY {
		t.FailNow()
	}

	if bytes.Compare(data, make([]byte, LENOF_PRIVATEKEY)) == 0 {
		t.FailNow()
	}
}

func TestPrivateKeySetString(t *testing.T) {
	pk1 := &PrivateKey{}
	pk1.Random()
	str := pk1.String()
	t.Log("PrivateKey1", str)

	pk2 := &PrivateKey{}
	err := pk2.SetString(str)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("PrivateKey2", pk2.String())
	if bytes.Compare(pk1.Data(), pk2.Data()) != 0 {
		t.FailNow()
	}
}

func TestPrivateKeyMnemonics(t *testing.T) {
	pk1 := &PrivateKey{}
	pk1.Random()
	t.Log("PrivateKey1", pk1.String())

	mnemonics := pk1.Mnemonics()
	t.Log("Mnemonics", mnemonics)

	pk2 := &PrivateKey{}
	err := pk2.SetMnemonics(mnemonics)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("PrivateKey2", pk2.String())
	if bytes.Compare(pk1.Data(), pk2.Data()) != 0 {
		t.FailNow()
	}
}

func TestPrivateKeyPublicKey(t *testing.T) {
	prik := &PrivateKey{}
	prik.Random()
	t.Log("PrivateKey", prik.String())

	pubk := prik.PublicKey()
	t.Log("PublicKey", pubk.String())

	data := pubk.Data()
	if len(data) != LENOF_PUBLICKEY {
		t.FailNow()
	}

	if bytes.Compare(data, make([]byte, LENOF_PUBLICKEY)) == 0 {
		t.FailNow()
	}
}

func (this *S) Abstract() []byte {
	return []byte(this.Word)
}

func TestPrivateKeySign(t *testing.T) {
	s := &S{"hello world"}
	prik := &PrivateKey{}
	prik.Random()
	sign := prik.Sign(s)
	t.Log("Signature", sign.String())

	pubk := prik.PublicKey()
	if !pubk.Verify(s, sign) {
		t.FailNow()
	}
}
