#!/usr/bin/env sh

 # Size in Kilobytes. Defaults to 1MB.
SIZE=$(($1 * 1024))

LC_ALL=C tr -dc "A-Za-z0-9 " < /dev/urandom | head -c $SIZE > $2
