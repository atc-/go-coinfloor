package coinfloor

import (
	"code.google.com/p/go.net/websocket"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"encoding/hex"
	"log"
	"math/big"
)

type Connecter interface {
	Connect() error
	Disconnect() error
}

type Sender interface {
	Send(msg interface{}) (int, error)
}

type Reader interface {
	Read(ty interface{}) (int, error)
}

type Connection struct {
	ws        *websocket.Conn
	Url       string
	Origin    string
	Connected bool
}

type Res struct {
	Tag       int    `json:"tag"`
	ErrorCode int    `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
}

type Req struct {
	Tag    int16  `json:"tag"`
	Method string `json:"method"`
}

type Auth struct {
	Tag    int16    `json:"tag"`
	Method string   `json:"method"`
	User   int      `json:"user_id"`
	Cookie string   `json:"cookie"`
	Nonce  string   `json:"nonce"`
	Sig    []string `json:"signature"`
}

type Welcome struct {
	Nonce  string `json:"nonce"`
	Notice string `json:"notice"`
}

/*
 * Convenience func for creating a connection and connecting to a server
 */
func Connect(url string, origin string) (con *Connection, err error) {
	con = new(Connection)
	con.Url = url
	con.Origin = origin
	err = con.Connect()
	con.Connected = err == nil
	return con, err
}

func (con *Connection) Connect() error {
	ws, err := websocket.Dial(con.Url, "", con.Origin)
	con.ws = ws
	return err
}

func (con *Connection) Disconnect() error {
	return con.ws.Close()
}

/*
 * Reads 512 bytes from the connection and writes to ty
 * returning the number read and optionally an error
 */
func (c *Connection) Read(ty interface{}) (int, error) {
	if !c.Connected {
		return -1, errors.New("Not connected")
	}

	msg := make([]byte, 512)
	n, err := c.ws.Read(msg)

	if err != nil {
		return n, err
	}
	return n, json.Unmarshal(msg[:n], ty)
}

/*
 * Serialises msg, then writes to the connection
 */
func (c *Connection) Send(msg interface{}) (int, error) {
	if !c.Connected {
		return -1, errors.New("Not connected")
	}

	b, e := Serialise(msg)
	if e != nil {
		return 0, e
	}
	log.Printf("Write: %s\n", b)
	return c.ws.Write(b)
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
	return int16(b[0] | b[1])
}

func Nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return string(b)
}

func NewKey(uid string, pass string) (prKey ecdsa.PrivateKey) {
	sha := sha256.New224()
	sha.Write([]byte(uid + pass))
	sum := sha.Sum(nil)
	log.Println("Hash is ", hex.EncodeToString(sum))
	prKey.D = new(big.Int).SetBytes(sum)
	prKey.PublicKey.Curve = elliptic.P224()
	prKey.PublicKey.X, prKey.PublicKey.Y = elliptic.P224().ScalarBaseMult(sum)
	return prKey
}

func NewMsg(userId string, srNonce string, clNonce string) string {
	return userId + srNonce + clNonce
}
