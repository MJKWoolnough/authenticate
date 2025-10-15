package authenticate_test

import (
	"fmt"
	"os"
	"time"

	"vimagination.zapto.org/authenticate"
)

func Example() {
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
