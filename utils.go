package crypto

type CryptoUtils interface {
	AddressFromBytes([]byte) Address
	PrivateKeyFromBytes([]byte) PrivateKey
	PrivateKeyNew() PrivateKey
	PublicKeyFromBytes([]byte) PublicKey
	SignatureFromBytes([]byte) Signature
}

var (
	CRYPTOUTILS = map[byte]CryptoUtils{}
)

func Regist(crypto byte, utils CryptoUtils) {
	CRYPTOUTILS[crypto] = utils
}

func GetCryptoUtils(crypto byte) (utils CryptoUtils) {
	utils, ok := CRYPTOUTILS[crypto]
	if !ok {
		return nil
	}

	return
}

func AddressFromBytes(bytes []byte) Address {
	if len(bytes) == 0 {
		return nil
	}

	utils := GetCryptoUtils(bytes[0])
	if utils == nil {
		return nil
	}

	return utils.AddressFromBytes(bytes[1:])
}

func PrivateKeyFromBytes(bytes []byte) PrivateKey {
	if len(bytes) == 0 {
		return nil
	}

	utils := GetCryptoUtils(bytes[0])
	if utils == nil {
		return nil
	}

	return utils.PrivateKeyFromBytes(bytes[1:])
}

func PrivateKeyNew(crypto byte) PrivateKey {
	utils := GetCryptoUtils(crypto)
	if utils == nil {
		return nil
	}

	return utils.PrivateKeyNew()
}

func PublicKeyFromBytes(bytes []byte) PublicKey {
	if len(bytes) == 0 {
		return nil
	}

	utils := GetCryptoUtils(bytes[0])
	if utils == nil {
		return nil
	}

	return utils.PublicKeyFromBytes(bytes[1:])
}

func SignatureFromBytes(bytes []byte) Signature {
	if len(bytes) == 0 {
		return nil
	}

	utils := GetCryptoUtils(bytes[0])
	if utils == nil {
		return nil
	}

	return utils.SignatureFromBytes(bytes[1:])
}
