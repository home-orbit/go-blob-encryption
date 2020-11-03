default: build

build:
	@mkdir -p bin
	go build -o ./bin/ ./...

install:
	go install ./...

test: unit-test integration-test

unit-test:
	go test ./...

TMPDIR:=$(shell mktemp -d)

integration-test: build
	# Integration Test: Basic Round-Trip
	@testdata/randomChars.sh 2048 > "$(TMPDIR)/2048.txt"

	@bin/blobcrypt -encrypt "$(TMPDIR)/2048.txt" "$(TMPDIR)/2048.enc" \
	  || { echo "FAIL: File could not be encrypted"; exit 1; }
	
	@bin/blobcrypt -decrypt "$(TMPDIR)/2048.enc" | diff -q - "$(TMPDIR)/2048.txt" \
	  && { echo "PASS"; echo; } \
	  || { echo "FAIL: File is not decryptable"; exit 1; }

	# Integration Test: File using Convergence Secret is decryptable.
	@bin/blobcrypt -encrypt -cs "secret" "$(TMPDIR)/2048.txt" "$(TMPDIR)/2048.cs.enc" \
	  || { echo "FAIL: File could not be encrypted using convergence secret"; exit 1; }
	
	@bin/blobcrypt -decrypt "$(TMPDIR)/2048.cs.enc" | diff -q - "$(TMPDIR)/2048.txt" \
	  && { echo "PASS"; echo; } \
	  || { echo "FAIL: File is not decryptable, or did not match original"; exit 1; }

	# Integration Test: Convergence Secret must cause encrypted file to differ.
	@(diff -q "$(TMPDIR)/2048.enc" "$(TMPDIR)/2048.cs.enc") \
	  && { echo "FAIL: Files do not differ"; exit 1; } \
	  || { echo "PASS"; echo; }

	@-rm -rf $(TMPDIR)
