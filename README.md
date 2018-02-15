# Boneh–Lynn–Shacham Signature Scheme
[![Build Status](https://travis-ci.org/enzoh/go-bls.svg?branch=master)](https://travis-ci.org/enzoh/go-bls?branch=master)

## Disclaimer
I wrote this library to familiarize myself with some basic pairing-based cryptosystems. I am not a cryptographer. Nor has any cryptographer that I know reviewed this code. I would advise against using it in any production system.

## Overview
This library provides a high-level API for signing and verifying message digests using the BLS signature scheme. It includes support for aggregate signatures, threshold signatures, and ring signatures.

## Prerequisites
Install the pairing-based crypto library from Stanford.
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

## License

GPLv3
