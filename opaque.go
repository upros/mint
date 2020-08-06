package mint

import (
	"github.com/codahale/etm"
)

type EnvU struct {
	PubU  []byte `tls:"head=2,min=1"`
	PrivU []byte `tls:"head=2,min=1"`
	PubS  []byte `tls:"head=2,min=1"`
}

func AuthEnc(pakeid, RwdU, EnvU []byte) []byte {
	aead, _ := etm.NewAES128SHA256(RwdU)
	// OWEN: derive nonce, aad from pakeid??
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}
	aad := nonce

	EncU := aead.Seal(nil, nonce, EnvU, aad)
	return EncU
}

func AuthDec(pakeid, RwdU, EncU []byte) []byte {
	aead, _ := etm.NewAES128SHA256(RwdU)
	// OWEN: derive nonce, aad from pakeid??
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}
	aad := nonce
	EnvU, _ := aead.Open(nil, nonce, EncU, aad)
	return EnvU
}
