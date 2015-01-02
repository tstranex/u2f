# FIDO U2F Go Library

This Go package implements the parts of the FIDO U2F specification needed to
enable FIDO U2F on a server.

## Features

- Native Go implementation
- No dependancies other than the Go standard library
- Token attestation certificate verification

## Documentation

Please visit http://godoc.org/github.com/tstranex/u2f

## Installation

```
go get github.com/tstranex/u2f
```

## Example

See the code in the u2fdemo directory for an full example server.

```
go install github.com/tstranex/u2f/u2fdemo
./bin/u2fdemo
```

Open http://localhost:3483 in Chrome.

## License

The FIDO U2F Go library is licensed under the MIT License.
