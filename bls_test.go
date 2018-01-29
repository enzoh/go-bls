/**
 * File        : bls_test.go
 * Description : Unit tests.
 * Copyright   : Copyright (c) 2017-2018 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module provides unit tests for the Boneh-Lynn-Shacham signature scheme.
 */

package bls

import (
	"crypto/sha256"
	"math/rand"
	"testing"
	"time"
)

func TestSignVerify(test *testing.T) {

	message := "This is a message."

	// Generate key pair.
	params := GenParamsTypeA(160, 512)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	key, secret, err := GenKeys(system)
	if err != nil {
		test.Fatal(err)
	}

	// Sign message.
	hash := sha256.Sum256([]byte(message))
	signature, err := Sign(hash, secret)
	if err != nil {
		test.Fatal(err)
	}

	// Verify signature.
	valid, err := Verify(signature, hash, key)
	if err != nil {
		test.Fatal(err)
	}
	if !valid {
		test.Fatal("Failed to verify signature.")
	}

	// Clean up.
	key.Free()
	secret.Free()
	system.Free()
	pairing.Free()
	params.Free()

}

func TestAggregateVerify(test *testing.T) {

	messages := []string{
		"This is a message.",
		"This is another message.",
		"This is yet another message.",
		"These messages are unique.",
	}
	n := len(messages)

	// Generate key pairs.
	params, err := GenParamsTypeD(9563, 512)
	if err != nil {
		test.Fatal(err)
	}
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	keys := make([]PublicKey, n)
	secrets := make([]PrivateKey, n)
	for i := 0; i < n; i++ {
		keys[i], secrets[i], err = GenKeys(system)
		if err != nil {
			test.Fatal(err)
		}
	}

	// Sign messages.
	hashes := make([][sha256.Size]byte, n)
	signatures := make([][]byte, n)
	for i := 0; i < n; i++ {
		hashes[i] = sha256.Sum256([]byte(messages[i]))
		signatures[i], err = Sign(hashes[i], secrets[i])
		if err != nil {
			test.Fatal(err)
		}
	}

	// Aggregate signatures.
	signature, err := Aggregate(signatures, system)
	if err != nil {
		test.Fatal(err)
	}

	// Verify aggregate signature.
	valid, err := AggregateVerify(signature, hashes, keys)
	if err != nil {
		test.Fatal(err)
	}
	if !valid {
		test.Fatal("Failed to verify signature.")
	}

	// Clean up.
	for i := 0; i < n; i++ {
		keys[i].Free()
		secrets[i].Free()
	}
	system.Free()
	pairing.Free()
	params.Free()

}

func TestThresholdSignature(test *testing.T) {

	message := "This is a message."

	// Generate key shares.
	params := GenParamsTypeF(256)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		test.Fatal(err)
	}
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(20) + 1
	t := rand.Intn(n) + 1
	groupKey, memberKeys, groupSecret, memberSecrets, err := GenKeyShares(t, n, system)
	if err != nil {
		test.Fatal(err)
	}

	// Select group members.
	memberIds := rand.Perm(n)[:t]

	// Sign message.
	hash := sha256.Sum256([]byte(message))
	signatures := make([][]byte, t)
	for i := 0; i < t; i++ {
		signatures[i], err = Sign(hash, memberSecrets[memberIds[i]])
		if err != nil {
			test.Fatal(err)
		}
	}

	// Recover signature.
	signature, err := Threshold(signatures, memberIds, system)
	if err != nil {
		test.Fatal(err)
	}

	// Verify signature.
	valid, err := Verify(signature, hash, groupKey)
	if err != nil {
		test.Fatal(err)
	}
	if !valid {
		test.Fatal("Failed to verify signature.")
	}

	// Clean up.
	groupKey.Free()
	groupSecret.Free()
	for i := 0; i < n; i++ {
		memberKeys[i].Free()
		memberSecrets[i].Free()
	}
	system.Free()
	pairing.Free()
	params.Free()

}

func BenchmarkVerify(benchmark *testing.B) {

	message := "This is a message."

	// Generate key pair.
	params := GenParamsTypeF(160)
	pairing := GenPairing(params)
	system, err := GenSystem(pairing)
	if err != nil {
		benchmark.Fatal(err)
	}
	key, secret, err := GenKeys(system)
	if err != nil {
		benchmark.Fatal(err)
	}

	// Sign message.
	hash := sha256.Sum256([]byte(message))
	signature, err := Sign(hash, secret)
	if err != nil {
		benchmark.Fatal(err)
	}

	// Verify signature.
	benchmark.StartTimer()
	for i := 0; i < benchmark.N; i++ {
		Verify(signature, hash, key)
	}
	benchmark.StopTimer()

	// Clean up.
	key.Free()
	secret.Free()
	system.Free()
	pairing.Free()
	params.Free()

}
