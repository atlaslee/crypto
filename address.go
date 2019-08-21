package crypto

type Address interface {
	Crypto() byte
	Data() []byte
	SetData([]byte) error
	String() string
	SetString(string) error
	Validate(PublicKey) bool
	Bytes() []byte
	SetBytes([]byte) error
}
