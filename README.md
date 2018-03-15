# authenticate
--
    import "github.com/MJKWoolnough/authenticate"

Package authenticate provides a simple interface to encrypt and authenticate a
### message

## Usage

```go
const (
	ErrInvalidAES  errors.Error = "invalid AES key, must be 16, 24 or 32 bytes"
	ErrInvalidData errors.Error = "invalid cipher text"
	ErrExpired     errors.Error = "data expired"
)
```
Errors

#### type Codec

```go
type Codec struct {
}
```

Codec represents an initilised encoder/decoder

#### func  NewCodec

```go
func NewCodec(key []byte, maxAge time.Duration) (*Codec, error)
```
NewCodec takes the encryption key, which should be 16, 24 or 32 bytes long, and
an optional duration to create a new Codec.

The optional Duration is used to only allow messages to only be valid while it
is younger than the given time.

#### func (*Codec) Decode

```go
func (c *Codec) Decode(cipherText, dst []byte) ([]byte, error)
```
Decode takes a ciphertext slice and a destination buffer and returns the
decrypted data or an error if the ciphertext is invalid or expired.

If the destination buffer is too small, or nil, it will be allocated
accordingly.

#### func (*Codec) Encode

```go
func (c *Codec) Encode(data, dst []byte) []byte
```
Encode takes a data slice and a destination buffer and returns the encrypted
data.

If the destination buffer is too small, or nil, it will be allocated
accordingly.

#### func (*Codec) Overhead

```go
func (c *Codec) Overhead() int
```
Overhead returns the maximum number of bytes that the ciphertext will be longer
than the plain text
