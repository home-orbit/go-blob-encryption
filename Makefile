default: build

build:
	mkdir -p bin
	go build -o ./bin/ ./...

install:
	go install ./...
