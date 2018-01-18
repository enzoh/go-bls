package main

import (
	"crypto/sha256"
	"math/rand"
	"time"

	"github.com/enzoh/go-bls"
)

func main() {

	// Generate a BLS cryptosystem.
	params := bls.GenParamsTypeF(256)
	defer params.Free()
	pairing := bls.GenPairing(params)
	defer pairing.Free()
	system, err := bls.GenSystem(pairing)
	if err != nil {
		panic(err)
	}
	defer system.Free()

	// Generate a BLS key pair using a 3-out-of-5 partition scheme.
	members := 5
	threshold := 3
	groupPubKey, memberPubKeys, groupSecKey, memberSecKeys, err := bls.GenKeyShares(threshold, members, system)
	if err != nil {
		panic(err)
	}
	defer groupPubKey.Free()
	defer groupSecKey.Free()
	for i := 0; i < members; i++ {
		defer memberPubKeys[i].Free()
		defer memberSecKeys[i].Free()
	}

	// Select group members to participate in a threshold signature.
	rand.Seed(time.Now().UnixNano())
	participants := rand.Perm(members)[:threshold]

	// Let each participant sign a message with their share of the secret key.
	message := "This is a message."
	hash := sha256.Sum256([]byte(message))
	signatures := make([][]byte, threshold)
	for i := 0; i < threshold; i++ {
		signatures[i], err = bls.Sign(hash, memberSecKeys[participants[i]])
		if err != nil {
			panic(err)
		}
	}

	// Recover a group signature from the signature shares.
	signature, err := bls.Recover(signatures, participants, system)
	if err != nil {
		panic(err)
	}

	// Validate the signature against the group public key.
	valid, err := bls.Verify(signature, hash, groupPubKey)
	if err != nil {
		panic(err)
	}
	if !valid {
		panic("Invalid signature.")
	}

}
