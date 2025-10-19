// Package authenticate provides a simple interface to encrypt and authenticate a message.
package authenticate // import "vimagination.zapto.org/authenticate"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var timeNow = time.Now

const nonceSize = 12

// Codec represents an initialised encoder/decoder.
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
		dst = make([]byte, nonceSize, len(data)+c.Overhead())
	} else {
		dst = dst[:nonceSize]
	}

	t := timeNow()

	binary.LittleEndian.PutUint64(dst, uint64(t.Nanosecond())) // last four bytes are overridden
	binary.BigEndian.PutUint64(dst[4:], uint64(t.Unix()))

	return c.aead.Seal(dst, dst, data, nil)
}

// Decode takes a cipher text slice and a destination buffer and returns the
// decrypted data or an error if the cipher text is invalid or expired.
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
		return nil, fmt.Errorf("error opening cipher text: %w", err)
	}

	return dst, nil
}

func (c *Codec) Sign(data, dst []byte) []byte {
	if cap(dst) < len(data)+nonceSize {
		dst = make([]byte, nonceSize, len(data)+c.Overhead())
	} else {
		dst = dst[:len(data)+nonceSize]
	}

	nonce := dst[len(data) : len(data)+nonceSize]
	_ = append(dst[:0], data...)

	t := timeNow()

	binary.LittleEndian.PutUint64(nonce, uint64(t.Nanosecond())) // last four bytes are overridden
	binary.BigEndian.PutUint64(nonce[4:], uint64(t.Unix()))

	return c.aead.Seal(dst, nonce, nil, data)
}

func (c *Codec) Verify(data []byte) ([]byte, error) {
	o := c.Overhead()

	if len(data) < o {
		return nil, ErrInvalidData
	}

	plain := data[:len(data)-o]
	nonce := data[len(plain) : len(plain)+nonceSize]
	sig := data[len(plain)+nonceSize:]

	if c.maxAge > 0 {
		if t := timeNow().Sub(time.Unix(int64(binary.BigEndian.Uint64(nonce[4:12])), 0)); t > c.maxAge || t < 0 {
			return nil, ErrExpired
		}
	}

	if _, err := c.aead.Open(nil, nonce, sig, plain); err != nil {
		return nil, fmt.Errorf("error verifying signature: %w", err)
	}

	return plain, nil
}

// Overhead returns the maximum number of bytes that the cipher text will be
// longer than the plain text.
func (c *Codec) Overhead() int {
	return c.aead.Overhead() + nonceSize
}

// Errors.
var (
	ErrInvalidAES  = errors.New("invalid AES key, must be 16, 24 or 32 bytes")
	ErrInvalidData = errors.New("invalid cipher text")
	ErrExpired     = errors.New("data expired")
)
