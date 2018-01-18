/**
 * File        : util_test.go
 * Description : Unit tests.
 * Copyright   : Copyright (c) 2017-2018 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module provides unit tests for functions involving hashes.
 */

package bls

import (
	"crypto/sha256"
	"math/rand"
	"testing"
	"time"
)

func TestSortHashes(test *testing.T) {
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(100)
	hashes, err := randomHashes(n)
	if err != nil {
		test.Fatal(err)
	}
	sortHashes(hashes)
	for i := 0; i < n-1; i++ {
		if compare(hashes[i], hashes[i+1]) == 1 {
			test.Fatal(hashes)
		}
	}
}

func TestUniqueHashes(test *testing.T) {
	words := []string{"Apple", "Bananna", "Kiwi", "Mango", "Orange", "Pineapple", "Tangerine"}
	hashes := make([][sha256.Size]byte, len(words))
	for i := range words {
		hashes[i] = sha256.Sum256([]byte(words[i]))
	}
	if !uniqueHashes(hashes) {
		test.Fatal("unexpected duplicate hash")
	}
}
