package coinfloor

import (
	"encoding/json"
	"crypto/rand"
)

type Cookie struct {
}

type Req struct {
	Tag int `json:"tag"`
	Method string `json:"method"`
}

type Auth struct {
	Tag int16 `json:"tag"`
	Method string `json:"method"`
	User int `json:"user_id"`
	Cookie string `json:"cookie"`
	Nonce []byte `json:"nonce"`
	Sig []string `json:"signature"`
}

func Serialise(v interface{}) (b []byte, e error) {
	b, e = json.Marshal(v)
	return b, e
}

func Tag() (n int16) {
	b := make([]byte, 2)
	rand.Read(b)
	return int16(b[0] & b[1])
}

func Nonce() ([]byte) {
    b := make([]byte, 16)
    rand.Read(b)
	return b
}
