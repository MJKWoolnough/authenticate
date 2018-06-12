// Package authenticate provides a simple interface to encrypt and authenticate a message
package authenticate // import "vimagination.zapto.org/authenticate"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"time"

	"vimagination.zapto.org/errors"
)

var timeNow = time.Now

const nonceSize = 12

// Codec represents an initilised encoder/decoder
type Codec struct {
	aead   cipher.AEAD
	maxAge time.Duration
}

// NewCodec takes the encryption key, which should be 16, 24 or 32 bytes long,
// and an optional duration to create a new Codec.
//
// The optional Duration is used to only allow messages to only be valid while
// it is younger than the given time.
func NewCodec(key []byte, maxAge time.Duration) (*Codec, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, ErrInvalidAES
	}
	a := make([]byte, len(key))
	copy(a, key)
	block, _ := aes.NewCipher(a)
	aead, _ := cipher.NewGCMWithNonceSize(block, nonceSize)
	return &Codec{
		aead:   aead,
		maxAge: maxAge,
	}, nil
}

// Encode takes a data slice and a destination buffer and returns the encrypted
// data.
//
// If the destination buffer is too small, or nil, it will be allocated accordingly.
func (c *Codec) Encode(data, dst []byte) []byte {
	if cap(dst) < nonceSize {
		dst = make([]byte, nonceSize, nonceSize+len(data)+c.aead.Overhead())
	} else {
		dst = dst[:nonceSize]
	}
	t := timeNow()
	binary.LittleEndian.PutUint64(dst, uint64(t.Nanosecond())) // last four bytes are overriden
	binary.BigEndian.PutUint64(dst[4:], uint64(t.Unix()))

	return c.aead.Seal(dst, dst, data, nil)
}

// Decode takes a ciphertext slice and a destination buffer and returns the
// decrypted data or an error if the ciphertext is invalid or expired.
//
// If the destination buffer is too small, or nil, it will be allocated accordingly.
func (c *Codec) Decode(cipherText, dst []byte) ([]byte, error) {
	if len(cipherText) < nonceSize {
		return nil, ErrInvalidData
	}

	timestamp := time.Unix(int64(binary.BigEndian.Uint64(cipherText[4:12])), 0)

	if c.maxAge > 0 {
		if t := timeNow().Sub(timestamp); t > c.maxAge || t < 0 {
			return nil, ErrExpired
		}
	}

	var err error
	dst, err = c.aead.Open(dst, cipherText[:nonceSize], cipherText[nonceSize:], nil)

	if err != nil {
		return nil, errors.WithContext("error opening ciphertext: ", err)
	}

	return dst, nil
}

// Overhead returns the maximum number of bytes that the ciphertext will be
// longer than the plain text
func (c *Codec) Overhead() int {
	return c.aead.Overhead() + nonceSize
}

// Errors
const (
	ErrInvalidAES  errors.Error = "invalid AES key, must be 16, 24 or 32 bytes"
	ErrInvalidData errors.Error = "invalid cipher text"
	ErrExpired     errors.Error = "data expired"
)
