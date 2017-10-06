package authenticate

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"time"
)

var timeNow = time.Now

const nonceSize = 12

type Codec struct {
	aead   cipher.AEAD
	maxAge time.Duration
}

func NewCodec(key []byte, maxAge time.Duration) (*Codec, error) {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return nil, errInvalidAES
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

func (c *Codec) Decode(cipherText, dst []byte) ([]byte, error) {
	if len(cipherText) < nonceSize {
		return nil, errInvalidData
	}

	timestamp := time.Unix(int64(binary.BigEndian.Uint64(cipherText[4:12])), 0)

	if c.maxAge > 0 {
		if t := timeNow().Sub(timestamp); t > c.maxAge || t < 0 {
			return nil, errExpired
		}
	}

	var err error
	dst, err = c.aead.Open(dst, cipherText[:nonceSize], cipherText[nonceSize:], nil)

	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (c *Codec) Overhead() int {
	return c.aead.Overhead() + nonceSize
}

var (
	errInvalidAES  = errors.New("invalid AES key, must be 16, 24 or 32 bytes")
	errInvalidData = errors.New("invalid cipher text")
	errExpired     = errors.New("data expired")
)
