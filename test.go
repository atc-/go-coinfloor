package main

import (
	"bitecdsa"
	"coinfloor"
	"crypto/rand"
    "encoding/base64"
    "log"
	"math/big"
	"os"
	"strconv"
)

func main () {
	args := os.Args[1:]

	if len(args) != 3 {
		log.Fatal("Not enough arguments: ", args)
		return
	}

	userId, uidErr := strconv.ParseInt(args[0], 10, 64)

	if uidErr != nil {
		log.Fatal("Invalid user id ", userId, uidErr)
	}
	
	pass, cookie := args[1], args[2]
	log.Println("Given userId, pass and cookie: ", userId, pass, cookie)
	con, _ := coinfloor.Connect("ws://api.coinfloor.co.uk:80/", "http://atc.gd/")

	welcome := new(coinfloor.Welcome)
	con.Read(&welcome)

	log.Println("Welcome is ", welcome)

    srNonce, clNonce := dec(welcome.Nonce), []byte(coinfloor.Nonce())

	uid := new(big.Int).SetInt64(userId)
    key := coinfloor.NewKey(uid, pass)
    msg := coinfloor.BuildMessage(uid, srNonce, clNonce)

	log.Println("Nonces are ", srNonce, clNonce, len(srNonce), len(clNonce))
    log.Println("key is ", key)
	log.Println("msg is ", msg, len(msg))

    r, s, err := bitecdsa.Sign(rand.Reader, key, msg)
	sig := []string{enc(r.Bytes()), enc(s.Bytes())}

    t := coinfloor.Auth {
        Tag: coinfloor.Tag(), 
        Method: "Authenticate",
        User: 134, 
        Cookie: cookie,
        Nonce: enc([]byte(clNonce)),
        Sig: sig,
    }

	log.Println("Auth is ", t)

    if _, err := con.Send(t); err != nil {
        log.Fatal("Error authorizing: ", err)
    }

    for {
        var res coinfloor.Res
        _, err = con.Read(&res)

        if err != nil {
            log.Fatal(err)
        }

        log.Println("Received: ", res)
    }   
}

func enc(src []byte) (string) {
	return base64.StdEncoding.EncodeToString(src)
}

func dec(src string) ([]byte) {
	d, _ := base64.StdEncoding.DecodeString(src)
	return d
}
