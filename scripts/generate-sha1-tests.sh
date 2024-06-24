#!/bin/bash
#set -e

# The goal of this script is to generate test cases for the sha1 hashing algorithm.
# It relies on openssl's own sha1 hashing algorithm, considered correct, to hash inputs.
# Inputs are created randomly : they are strings of hexadecimals caracters of random length 1-256.

# `cargo test` needs the generated file to pass.

for i in {0..10000}
do
    l=$((1 + $RANDOM % 256))
    bytes=$(openssl rand -hex $l)
    line=($(echo -n $bytes | xxd -r -p | openssl dgst -sha1 -r))
    echo $bytes ${line[0]} >> sha1.generated-testcases
done