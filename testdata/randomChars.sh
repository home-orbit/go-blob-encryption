#!/usr/bin/env sh

# Usage: randomChars.sh SIZE
#   Outputs SIZE kilobytes of printable ASCII characters filtered from /dev/urandom
SIZE=$(($1 * 1024))

LC_ALL=C tr -dc "A-Za-z0-9 \n\-_" < /dev/urandom | head -c $SIZE
