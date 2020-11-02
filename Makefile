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
	# Integration Test: Round-trip a 2MB file of random ASCII, call diff on result.
	@testdata/randomChars.sh 2048 > "$(TMPDIR)/2048.txt"
	@bin/blobcrypt -encrypt "$(TMPDIR)/2048.txt" "$(TMPDIR)/2048.enc"
	@bin/blobcrypt -decrypt "$(TMPDIR)/2048.enc" | diff - "$(TMPDIR)/2048.txt"
	# * PASS
	@-rm -rf $(TMPDIR)
