#!/usr/bin/env sh

# Usage: randomChars.sh SIZE
#   Outputs SIZE kilobytes of base64 characters from /dev/urandom
SIZE=$(($1 * 768))

# base64 is used, as filtering for ASCII characters with tr was highly inefficient
head -c $SIZE < /dev/urandom | base64
