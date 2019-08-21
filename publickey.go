package crypto

type PublicKey interface {
	Crypto() byte
	Data() []byte
	SetData([]byte) error
	String() string
	SetString(string) error
	Address() Address
	Verify(Signable, Signature) bool
	Bytes() []byte
	SetBytes([]byte) error
}
