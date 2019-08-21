package crypto

type PrivateKey interface {
	Crypto() byte
	Data() []byte
	SetData([]byte) error
	Mnemonics() []string
	SetMnemonics([]string) error
	String() string
	SetString(string) error
	Random()
	PublicKey() PublicKey
	Sign(Signable) Signature
	Bytes() []byte
	SetBytes([]byte) error
}
