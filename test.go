package main

import (
	"coinfloor"
	"crypto/ecdsa"
	"crypto/rand"
    "encoding/base64"
    "log"
	"os"
)

func main () {
	args := os.Args[1:]

	if len(args) != 3 {
		log.Fatal("Not enough arguments: ", args)
		return
	}

	userId, pass, cookie := args[0], args[1], args[2]
	con, _ := coinfloor.Connect("ws://api.coinfloor.co.uk:80/", "http://atc.gd/")
	
	welcome := new(coinfloor.Welcome)
	con.Read(&welcome)

	log.Println("Welcome is ", welcome)

    srNonce, clNonce := welcome.Nonce, coinfloor.Nonce()

    key := coinfloor.NewKey(userId, pass)
    msg := coinfloor.NewMsg(userId, srNonce, clNonce)

    log.Println("key is ", key)

    r, s, err := ecdsa.Sign(rand.Reader, &key, msg)
	sig := []string{enc(r.String())[:40], enc(s.String())[:40]}

    log.Println("R, s, err are: ", r, s, err)

    t := coinfloor.Auth {
        Tag: coinfloor.Tag(), 
        Method: "Authenticate",
        User: 134, 
        Cookie: cookie,
        Nonce: clNonce,
        Sig: sig,
    }

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

func enc(src string) (string) {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

