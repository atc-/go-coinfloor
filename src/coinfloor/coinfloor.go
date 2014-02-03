package coinfloor

import (
	"encoding/json"
	"crypto/rand"
	"code.google.com/p/go.net/websocket" 
	"log"
)

type Connecter interface {
	Connect() (Connection, error)
}

type Sender interface {
	Send(msg interface{}) (int, error)
}

type Reader interface {
	Read(ty interface{}) (int, error)
}

type Connection struct {
	ws *websocket.Conn
	Url string
	Origin string
	Connected bool
}

type Res struct {
}

type Req struct {
	Tag int16 `json:"tag"`
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

type Welcome struct {
	Nonce string `json:"nonce"`
	Notice string `json:"notice"`
}

/*
 * Convenience func for creating and connecting to a server
 */
func Connect(url string, origin string) (con *Connection, err error) {
	con = new (Connection)
	con.Url = url
	con.Origin = origin
	return con.Connect()
}

func (con *Connection) Connect() (*Connection, error) {
	ws, err := websocket.Dial(con.Url, "", con.Origin)
	con.ws = ws
	return con, err
}

/*
 * Reads 512 bytes from the connection and writes to ty
 * returning the number read and optionally an error
 */
func (r *Connection) Read(ty interface{}) (int, error) {
	msg := make([]byte, 512)
	n, err := r.ws.Read(msg)
	
	if err != nil {
		return n, err
	}
	return n, json.Unmarshal(msg[:n], ty)
}

/*
 * Serialises msg, then writes to the connection
 */
func (con *Connection) Send(msg interface{}) (int, error) {
	b, e := Serialise(msg)
	if e != nil {
		return 0, e
	}
	log.Printf("Write: %s\n", b)
	return con.ws.Write(b)
}

/*
 * Convert v to a json string
 */
func Serialise(v interface{}) (b []byte, e error) {
	b, e = json.Marshal(v)
	return b, e
}

/*
 * Generate a random 16-bit integer for the message tag
 */
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

