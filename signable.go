package crypto

type Signable interface {
	Abstract() []byte
}
