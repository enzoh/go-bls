# Boneh–Lynn–Shacham Signature Scheme
[![Build Status](https://travis-ci.org/enzoh/go-bls.svg?branch=master)](https://travis-ci.org/enzoh/go-bls?branch=master)

## Overview
This library provides a high-level API for signing and verifying message digests using the Boneh–Lynn–Shacham signature scheme.

## Prerequisites
Install the pairing-based cryptography library.
```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
if [[ $(sha256sum pbc-0.5.14.tar.gz) = \
	772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2* ]]
then
	tar xf pbc-0.5.14.tar.gz
	pushd pbc-0.5.14
	sh configure
	make
	sudo make install
	popd
else
	echo 'Cannot download PBC library from crypto.stanford.edu.'
	exit 1
fi
```

## Install
Install this library using the `go get` command.
```bash
go get github.com/enzoh/go-bls
```

## Usage
Check out the [documentation](https://godoc.org/github.com/enzoh/go-bls).

## Example
The following example shows how to validate a threshold signature.
```go
package main

import (
	"math/rand"
	"time"

	"github.com/enzoh/go-bls"
	"github.com/ethereum/go-ethereum/crypto"
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
	hash := crypto.Keccak256Hash([]byte(message))
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
```
