/**
 * File        : util.go
 * Description : Functions involving hashes.
 * Copyright   : Copyright (c) 2017 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module provides some commonly-used functions involving hashes.
 */

package bls

import (
	"crypto/rand"

	"github.com/ethereum/go-ethereum/common"
)

func randomHash() (*common.Hash, error) {
	bytes := make([]byte, common.HashLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	hash := common.BytesToHash(bytes)
	return &hash, nil
}

func randomHashes(n int) ([]common.Hash, error) {
	hashes := make([]common.Hash, n)
	for i := range hashes {
		ptr, err := randomHash()
		hashes[i] = *ptr
		if err != nil {
			return nil, err
		}
	}
	return hashes, nil
}

func sortHashes(hashes []common.Hash) {
	n := len(hashes)
	quicksort(hashes, 0, n-1)
}

func quicksort(hashes []common.Hash, l int, r int) {
	if l < r {
		pivot := hashes[(l+r)/2].Big()
		i := l
		j := r
		var tmp common.Hash
		for i <= j {
			for hashes[i].Big().Cmp(pivot) == -1 {
				i++
			}
			for hashes[j].Big().Cmp(pivot) == 1 {
				j--
			}
			if i <= j {
				tmp = hashes[i]
				hashes[i] = hashes[j]
				hashes[j] = tmp
				i++
				j--
			}
		}
		if l < j {
			quicksort(hashes, l, j)
		}
		if i < r {
			quicksort(hashes, i, r)
		}
	}
}

func uniqueHashes(hashes []common.Hash) bool {
	n := len(hashes)
	c := make([]common.Hash, n)
	copy(c, hashes)
	sortHashes(c)
	for i := 0; i < n-1; i++ {
		if c[i].Big().Cmp(c[i+1].Big()) == 0 {
			return false
		}
	}
	return true
}
