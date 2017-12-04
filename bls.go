/**
 * File        : bls.go
 * Description : Boneh-Lynn-Shacham signature scheme.
 * Copyright   : Copyright (c) 2017 DFINITY Stiftung. All rights reserved.
 * Maintainer  : Enzo Haussecker <enzo@dfinity.org>
 * Stability   : Stable
 *
 * This module implements the Boneh-Lynn-Shacham signature scheme.
 */

package bls

import (
	"errors"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
)

/*
#cgo LDFLAGS: -lgmp -lpbc
#include <pbc/pbc.h>

int callback(pbc_cm_t cm, void *data) {
	pbc_param_init_d_gen(data, cm);
	return 1;
}

int search(pbc_param_ptr params, unsigned int d, unsigned int bitlimit) {
	int m = d % 4;
	if (d == 0 || m == 1 || m == 2) {
		pbc_die("Discriminant must be 0 or 3 mod 4 and positive.");
	}
	return pbc_cm_search_d(callback, params, d, bitlimit);
}
*/
import "C"

var sizeOfElement = C.size_t(unsafe.Sizeof(C.struct_element_s{}))
var sizeOfParams = C.size_t(unsafe.Sizeof(C.struct_pbc_param_s{}))
var sizeOfPairing = C.size_t(unsafe.Sizeof(C.struct_pairing_s{}))

type Element struct {
	get *C.struct_element_s
}

type Params struct {
	get *C.struct_pbc_param_s
}

type Pairing struct {
	get *C.struct_pairing_s
}

type System struct {
	pairing         Pairing
	g               Element
	signatureLength int
}

type PublicKey struct {
	system System
	gx     Element
}

type PrivateKey struct {
	system System
	x      Element
}

// GenParamsTypeA -- Generate type A pairing parameters. This function allocates
// C structures on the C heap using malloc. It is the responsibility of the
// caller to prevent memory leaks by arranging for the C structures to be freed.
// More information about type A pairing parameters can be found in the PBC
// library manual: https://crypto.stanford.edu/pbc/manual/ch08s03.html.
func GenParamsTypeA(rbits int, qbits int) Params {

	// Generate pairing parameters.
	params := (*C.struct_pbc_param_s)(C.malloc(sizeOfParams))
	C.pbc_param_init_a_gen(params, C.int(rbits), C.int(qbits))

	// Return result.
	return Params{params}

}

// GenParamsTypeD -- Generate type D pairing parameters. This function allocates
// C structures on the C heap using malloc. It is the responsibility of the
// caller to prevent memory leaks by arranging for the C structures to be freed.
// More information about type D pairing parameters can be found in the PBC
// library manual: https://crypto.stanford.edu/pbc/manual/ch08s06.html.
func GenParamsTypeD(d uint, bitlimit uint) (Params, error) {

	// Generate pairing parameters.
	params := (*C.struct_pbc_param_s)(C.malloc(sizeOfParams))
	if C.search(params, C.uint(d), C.uint(bitlimit)) == 0 {
		return Params{}, errors.New("bls.GenParamsTypeD: No suitable curves for this discriminant.")
	}

	// Return result.
	return Params{params}, nil

}

// GenParamsTypeF -- Generate type F pairing parameters. This function allocates
// C structures on the C heap using malloc. It is the responsibility of the
// caller to prevent memory leaks by arranging for the C structures to be freed.
// More information about type F pairing parameters can be found in the PBC
// library manual: https://crypto.stanford.edu/pbc/manual/ch08s08.html.
func GenParamsTypeF(bits int) Params {

	// Generate pairing parameters.
	params := (*C.struct_pbc_param_s)(C.malloc(sizeOfParams))
	C.pbc_param_init_f_gen(params, C.int(bits))

	// Return result.
	return Params{params}

}

// GenPairing -- Generate a pairing from the given parameters. This function
// allocates C structures on the C heap using malloc. It is the responsibility
// of the caller to prevent memory leaks by arranging for the C structures to be
// freed.
func GenPairing(params Params) Pairing {

	// Generate pairing.
	pairing := (*C.struct_pairing_s)(C.malloc(sizeOfPairing))
	C.pairing_init_pbc_param(pairing, params.get)

	// Return result.
	return Pairing{pairing}

}

// GenSystem -- Generate a cryptosystem from the given pairing. This function
// allocates C structures on the C heap using malloc. It is the responsibility
// of the caller to prevent memory leaks by arranging for the C structures to be
// freed.
func GenSystem(pairing Pairing) (System, error) {

	// Generate cryptographically secure pseudorandom hash.
	hash, err := randomHash()
	if err != nil {
		return System{}, err
	}

	// Set system parameter.
	g := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G2(g, pairing.get)
	C.element_from_hash(g, unsafe.Pointer(&(*hash)[0]), C.int(common.HashLength))

	// Calculate signature length.
	signatureLength := int(C.pairing_length_in_bytes_compressed_G1(pairing.get))

	// Return result.
	return System{pairing, Element{g}, signatureLength}, nil

}

// GenKeys -- Generate a key pair from the given cryptosystem. This function
// allocates C structures on the C heap using malloc. It is the responsibility
// of the caller to prevent memory leaks by arranging for the C structures to be
// freed.
func GenKeys(system System) (PublicKey, PrivateKey, error) {

	// Generate cryptographically secure pseudorandom hash.
	hash, err := randomHash()
	if err != nil {
		return PublicKey{}, PrivateKey{}, err
	}

	// Set private key.
	x := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_Zr(x, system.pairing.get)
	C.element_from_hash(x, unsafe.Pointer(&(*hash)[0]), C.int(common.HashLength))

	// Calculate corresponding public key.
	gx := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G2(gx, system.pairing.get)
	C.element_pow_zn(gx, system.g.get, x)

	// Return result.
	return PublicKey{system, Element{gx}}, PrivateKey{system, Element{x}}, nil

}

// GenKeyShares -- Generate a key pair from the given cryptosystem and divide
// each key into n shares such that t shares can combine to produce a valid
// signature. This function allocates C structures on the C heap using malloc.
// It is the responsibility of the caller to prevent memory leaks by arranging
// for the C structures to be freed.
func GenKeyShares(t int, n int, system System) (PublicKey, []PublicKey, PrivateKey, []PrivateKey, error) {

	// Check threshold parameters.
	if t < 1 || n < t {
		return PublicKey{}, nil, PrivateKey{}, nil, errors.New("bls.GenKeyShares: Bad threshold parameters.")
	}

	// Generate polynomial.
	coeff := make([]*C.struct_element_s, t)
	var hash *common.Hash
	var err error
	for j := range coeff {

		// Generate cryptographically secure pseudorandom hash.
		hash, err = randomHash()
		if err != nil {
			return PublicKey{}, nil, PrivateKey{}, nil, err
		}

		// Set polynomial coefficient.
		coeff[j] = (*C.struct_element_s)(C.malloc(sizeOfElement))
		C.element_init_Zr(coeff[j], system.pairing.get)
		C.element_from_hash(coeff[j], unsafe.Pointer(&(*hash)[0]), C.int(common.HashLength))

	}

	// Calculate public and private key shares.
	keys := make([]PublicKey, n+1)
	secrets := make([]PrivateKey, n+1)
	var bytes []byte
	var ij C.mpz_t
	C.mpz_init(&ij[0])
	term := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_Zr(term, system.pairing.get)
	for i := 0; i < n+1; i++ {

		// Calcualte private key share.
		secrets[i].system = system
		secrets[i].x.get = (*C.struct_element_s)(C.malloc(sizeOfElement))
		C.element_init_Zr(secrets[i].x.get, system.pairing.get)
		C.element_set0(secrets[i].x.get)
		for j := 0; j < t; j++ {
			bytes = big.NewInt(0).Exp(big.NewInt(int64(i)), big.NewInt(int64(j)), nil).Bytes()
			if len(bytes) == 0 {
				C.mpz_set_si(&ij[0], 0)
			} else {
				C.mpz_import(&ij[0], C.size_t(len(bytes)), 1, 1, 1, 0, unsafe.Pointer(&bytes[0]))
			}
			C.element_mul_mpz(term, coeff[j], &ij[0])
			C.element_add(secrets[i].x.get, secrets[i].x.get, term)
		}

		// Calculate corresponding public key share.
		keys[i].system = system
		keys[i].gx.get = (*C.struct_element_s)(C.malloc(sizeOfElement))
		C.element_init_G2(keys[i].gx.get, system.pairing.get)
		C.element_pow_zn(keys[i].gx.get, system.g.get, secrets[i].x.get)

	}

	// Clean up.
	for j := range coeff {
		C.element_clear(coeff[j])
	}
	C.mpz_clear(&ij[0])
	C.element_clear(term)

	// Return result.
	return keys[0], keys[1:], secrets[0], secrets[1:], nil

}

// Sign -- Sign a hash using the private key.
func Sign(hash common.Hash, secret PrivateKey) ([]byte, error) {

	// Check signature length.
	if secret.system.signatureLength <= 0 {
		return nil, errors.New("bls.Sign: Signature length must be positive.")
	}

	// Calculate h.
	h := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(h, secret.system.pairing.get)
	C.element_from_hash(h, unsafe.Pointer(&hash[0]), C.int(common.HashLength))

	// Calculate sigma.
	sigma := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(sigma, secret.system.pairing.get)
	C.element_pow_zn(sigma, h, secret.x.get)

	// Convert sigma to bytes.
	signature := make([]byte, secret.system.signatureLength)
	C.element_to_bytes_compressed((*C.uchar)(unsafe.Pointer(&signature[0])), sigma)

	// Clean up.
	C.element_clear(h)
	C.element_clear(sigma)

	// Return result.
	return signature, nil

}

// Verify -- Verify the signature of a hash using the public key.
func Verify(signature []byte, hash common.Hash, key PublicKey) (bool, error) {

	// Check signature length.
	if key.system.signatureLength <= 0 {
		return false, errors.New("bls.Verify: Signature length must be positive.")
	}
	if key.system.signatureLength != len(signature) {
		return false, errors.New("bls.Verify: Signature length mismatch.")
	}

	// Calculate sigma.
	sigma := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(sigma, key.system.pairing.get)
	C.element_from_bytes_compressed(sigma, (*C.uchar)(unsafe.Pointer(&signature[0])))

	// Calculate left-hand side.
	lhs := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_GT(lhs, key.system.pairing.get)
	C.element_pairing(lhs, sigma, key.system.g.get)

	// Calculate h.
	h := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(h, key.system.pairing.get)
	C.element_from_hash(h, unsafe.Pointer(&hash[0]), C.int(common.HashLength))

	// Calculate right-hand side.
	rhs := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_GT(rhs, key.system.pairing.get)
	C.element_pairing(rhs, h, key.gx.get)

	// Equate left and right-hand side.
	C.element_invert(rhs, rhs)
	C.element_mul(lhs, lhs, rhs)
	result := C.element_is1(lhs) == 1

	// Clean up.
	C.element_clear(h)
	C.element_clear(lhs)
	C.element_clear(rhs)
	C.element_clear(sigma)

	// Return result.
	return result, nil

}

// Aggregate -- Aggregate signatures using the cryptosystem.
func Aggregate(signatures [][]byte, system System) ([]byte, error) {

	// Check list length.
	if len(signatures) == 0 {
		return nil, errors.New("bls.Aggregate: Empty list.")
	}

	// Check signature length.
	if system.signatureLength <= 0 {
		return nil, errors.New("bls.Aggregate: Signature length must be positive.")
	}
	for i := range signatures {
		if system.signatureLength != len(signatures[i]) {
			return nil, errors.New("bls.Aggregate: Signature length mismatch.")
		}
	}

	// Calculate sigma.
	sigma := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(sigma, system.pairing.get)
	C.element_from_bytes_compressed(sigma, (*C.uchar)(unsafe.Pointer(&signatures[0][0])))
	t := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(t, system.pairing.get)
	for i := 1; i < len(signatures); i++ {
		C.element_from_bytes_compressed(t, (*C.uchar)(unsafe.Pointer(&signatures[i][0])))
		C.element_mul(sigma, sigma, t)
	}

	// Convert sigma to bytes.
	signature := make([]byte, system.signatureLength)
	C.element_to_bytes_compressed((*C.uchar)(unsafe.Pointer(&signature[0])), sigma)

	// Clean up.
	C.element_clear(sigma)
	C.element_clear(t)

	// Return result.
	return signature, nil

}

// AggregateVerify -- Verify the aggregate signature of the hashes using the
// public keys.
func AggregateVerify(signature []byte, hashes []common.Hash, keys []PublicKey) (bool, error) {

	// Check list length.
	if len(hashes) == 0 {
		return false, errors.New("bls.AggregateVerify: Empty list.")
	}
	if len(hashes) != len(keys) {
		return false, errors.New("bls.AggregateVerify: List length mismatch.")
	}

	// Check signature length.
	if keys[0].system.signatureLength <= 0 {
		return false, errors.New("bls.AggregateVerify: Signature length must be positive.")
	}
	if keys[0].system.signatureLength != len(signature) {
		return false, errors.New("bls.AggregateVerify: Signature length mismatch.")
	}

	// Check uniqueness constraint.
	if !uniqueHashes(hashes) {
		return false, errors.New("bls.AggregateVerify: Hashes must be distinct.")
	}

	// Calculate sigma.
	sigma := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(sigma, keys[0].system.pairing.get)
	C.element_from_bytes_compressed(sigma, (*C.uchar)(unsafe.Pointer(&signature[0])))

	// Calculate left-hand side.
	lhs := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_GT(lhs, keys[0].system.pairing.get)
	C.element_pairing(lhs, sigma, keys[0].system.g.get)

	// Calculate right-hand side.
	h := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(h, keys[0].system.pairing.get)
	C.element_from_hash(h, unsafe.Pointer(&hashes[0][0]), C.int(common.HashLength))
	rhs := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_GT(rhs, keys[0].system.pairing.get)
	C.element_pairing(rhs, h, keys[0].gx.get)
	t := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_GT(t, keys[0].system.pairing.get)
	for i := 1; i < len(hashes); i++ {
		C.element_from_hash(h, unsafe.Pointer(&hashes[i][0]), C.int(common.HashLength))
		C.element_pairing(t, h, keys[i].gx.get)
		C.element_mul(rhs, rhs, t)
	}

	// Equate left and right-hand side.
	C.element_invert(rhs, rhs)
	C.element_mul(lhs, lhs, rhs)
	result := C.element_is1(lhs) == 1

	// Clean up.
	C.element_clear(h)
	C.element_clear(lhs)
	C.element_clear(rhs)
	C.element_clear(sigma)
	C.element_clear(t)

	// Return result.
	return result, nil

}

// Recover -- Recover a signature from the signature shares provided by the
// group members using the cryptosystem.
func Recover(signatures [][]byte, memberIds []int, system System) ([]byte, error) {

	// Check list length.
	if len(signatures) == 0 {
		return nil, errors.New("bls.Recover: Empty list.")
	}
	if len(signatures) != len(memberIds) {
		return nil, errors.New("bls.Recover: List length mismatch.")
	}

	// Check signature length.
	if system.signatureLength <= 0 {
		return nil, errors.New("bls.Recover: Signature length must be positive.")
	}
	for i := range signatures {
		if system.signatureLength != len(signatures[i]) {
			return nil, errors.New("bls.Recover: Signature length mismatch.")
		}
	}

	// Determine group order.
	n := (C.mpz_sizeinbase(&system.pairing.get.r[0], 2) + 7) / 8
	bytes := make([]byte, n)
	C.mpz_export(unsafe.Pointer(&bytes[0]), &n, 1, 1, 1, 0, &system.pairing.get.r[0])
	r := big.NewInt(0).SetBytes(bytes)

	// Calculate sigma.
	sigma := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(sigma, system.pairing.get)
	C.element_set1(sigma)
	var p *big.Int
	var q *big.Int
	u := big.NewInt(0)
	v := big.NewInt(0)
	var lambda C.mpz_t
	C.mpz_init(&lambda[0])
	s := (*C.struct_element_s)(C.malloc(sizeOfElement))
	C.element_init_G1(s, system.pairing.get)
	for i := range memberIds {

		// Calculate lambda.
		p = big.NewInt(1)
		q = big.NewInt(1)
		for j := range memberIds {
			if memberIds[i] != memberIds[j] {
				p.Mul(p, u.Neg(big.NewInt(int64(memberIds[j]+1))))
				q.Mul(q, v.Sub(big.NewInt(int64(memberIds[i]+1)), big.NewInt(int64(memberIds[j]+1))))
			}
		}
		bytes = u.Mod(u.Mul(u.Mod(p, r), v.Mod(v.ModInverse(q, r), r)), r).Bytes()
		if len(bytes) == 0 {
			C.mpz_set_si(&lambda[0], 0)
		} else {
			C.mpz_import(&lambda[0], C.size_t(len(bytes)), 1, 1, 1, 0, unsafe.Pointer(&bytes[0]))
		}

		// Update accumulator.
		C.element_from_bytes_compressed(s, (*C.uchar)(unsafe.Pointer(&signatures[i][0])))
		C.element_pow_mpz(s, s, &lambda[0])
		C.element_mul(sigma, sigma, s)

	}

	// Convert sigma to bytes.
	signature := make([]byte, system.signatureLength)
	C.element_to_bytes_compressed((*C.uchar)(unsafe.Pointer(&signature[0])), sigma)

	// Clean up.
	C.element_clear(s)
	C.mpz_clear(&lambda[0])
	C.element_clear(sigma)

	// Return result.
	return signature, nil

}

// Free -- Free the memory occupied by the element. The element cannot be used
// after calling this function.
func (element Element) Free() {
	C.element_clear(element.get)
}

// Free -- Free the memory occupied by the pairing parameters. The parameters
// cannot be used after calling this function.
func (params Params) Free() {
	C.pbc_param_clear(params.get)
}

// Free -- Free the memory occupied by the pairing. The pairing cannot be used
// after calling this function.
func (pairing Pairing) Free() {
	C.pairing_clear(pairing.get)
}

// Free -- Free the memory occupied by the cryptosystem. The cryptosystem cannot
// be used after calling this function.
func (system System) Free() {
	system.g.Free()
}

// Free -- Free the memory occupied by the public key. The public key cannot be
// used after calling this function.
func (key PublicKey) Free() {
	key.gx.Free()
}

// Free -- Free the memory occupied by the private key. The private key cannot
// be used after calling this function.
func (secret PrivateKey) Free() {
	secret.x.Free()
}
