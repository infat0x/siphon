# Installation

Siphon is written in Go and compiles to a single static binary.

## From Source
```bash
git clone https://github.com/infat0x/siphon.git
cd siphon
go build -o siphon main.go
sudo mv siphon /usr/local/bin/
```

## Verifying Installation
```bash
siphon -h
```

> [!NOTE]
> Ensure your `$GOPATH/bin` is added to your environment variables if you are installing via `go install`.
