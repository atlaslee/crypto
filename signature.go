package crypto

type Signature interface {
	Crypto() byte
	Address() Address
	Data() []byte
	SetData([]byte) error
	String() string
	SetString(string) error
	Hash() []byte
	HashString() string
	PublicKey() PublicKey
	Verify(Signable) bool
	Bytes() []byte
	SetBytes([]byte) error
}
