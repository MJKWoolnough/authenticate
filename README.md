# authenticate

[![CI](https://github.com/MJKWoolnough/authenticate/actions/workflows/go-checks.yml/badge.svg)](https://github.com/MJKWoolnough/authenticate/actions)
[![Go Reference](https://pkg.go.dev/badge/vimagination.zapto.org/authenticate.svg)](https://pkg.go.dev/vimagination.zapto.org/authenticate)
[![Go Report Card](https://goreportcard.com/badge/vimagination.zapto.org/authenticate)](https://goreportcard.com/report/vimagination.zapto.org/authenticate)

--
    import "vimagination.zapto.org/authenticate"

Package authenticate provides a simple interface to encrypt and authenticate a message.

## Highlights

 - Encrypt or sign data.
 - Optional data exiration.

## Usage

```go
package main

import (
	"fmt"
	"os"
	"time"

	"vimagination.zapto.org/authenticate"
)

func main() {
	codec, err := authenticate.NewCodec([]byte("!THIS IS MY KEY!"), time.Second)
	if err != nil {
		fmt.Println(err)

		return
	}

	message := []byte("My Message")
	encoded := codec.Encode(message, nil)

	if decoded, err := codec.Decode(encoded, nil); err != nil {
		fmt.Println(err)
	} else {
		os.Stdout.Write(decoded)
	}

	encoded[0] = encoded[0] ^ 128

	if decoded, err := codec.Decode(encoded, nil); err != nil {
		fmt.Printf("\n\n%s", err)
	} else {
		os.Stdout.Write(decoded)
	}

	// Output:
	// My Message
	//
	// error opening cipher text: cipher: message authentication failed
}
```

## Documentation

Full API docs can be found at:

https://pkg.go.dev/vimagination.zapto.org/authenticate
