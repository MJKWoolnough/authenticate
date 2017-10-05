package authenticate

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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

func (c *Codec) Encode(data []byte) string {
	dst := make([]byte, nonceSize, nonceSize+len(data)+c.aead.Overhead())
	t := timeNow()
	binary.LittleEndian.PutUint64(dst, uint64(t.Nanosecond())) // last four bytes are overriden
	binary.BigEndian.PutUint64(dst[4:], uint64(t.Unix()))

	dst = c.aead.Seal(dst, dst, data, nil)

	return base64.StdEncoding.EncodeToString(dst)
}

func (c *Codec) Decode(data string) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	} else if len(cipherText) < 12 {
		return nil, errInvalidData
	}

	timestamp := time.Unix(int64(binary.BigEndian.Uint64(cipherText[4:12])), 0)

	if c.maxAge > 0 {
		if t := timeNow().Sub(timestamp); t > c.maxAge || t < 0 {
			return nil, errExpired
		}
	}

	buf := make([]byte, 0, len(cipherText))

	buf, err = c.aead.Open(buf, cipherText[:12], cipherText[12:], nil)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

var (
	errInvalidAES  = errors.New("invalid AES key, must be 16, 24 or 32 bytes")
	errInvalidData = errors.New("invalid cipher text")
	errExpired     = errors.New("data expired")
)
