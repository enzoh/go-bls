/**
 * File        : util_test.go
 * Description : Unit tests.
 * Copyright   : Copyright (c) 2017 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module provides unit tests for functions involving hashes.
 */

package bls

import (
	"math/rand"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSortHashes(test *testing.T) {
	rand.Seed(time.Now().UnixNano())
	n := rand.Intn(10)
	hashes, err := randomHashes(n)
	if err != nil {
		test.Fatal(err)
	}
	sortHashes(hashes)
	for i := 0; i < n-1; i++ {
		if hashes[i].Big().Cmp(hashes[i+1].Big()) == 1 {
			test.Fatal(hashes)
		}
	}
}

func TestUniqueHashes(test *testing.T) {
	words := []string{"Kiwi", "Apple", "Orange", "Peach", "Bananna"}
	hashes := make([]common.Hash, len(words))
	for i := range words {
		hashes[i] = crypto.Keccak256Hash([]byte(words[i]))
	}
	if !uniqueHashes(hashes) {
		test.Fatal("Unexpected duplicate hash.")
	}
}
