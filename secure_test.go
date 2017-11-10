package authenticate

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

var times []time.Time

func init() {
	timeNow = func() time.Time {
		t := times[0]
		times = times[1:]
		return t
	}
}

func TestSecureEncode(t *testing.T) {
	tn := time.Date(1985, time.July, 2, 14, 25, 0, 0, time.UTC)
	tests := []struct {
		Key                    []byte
		CodecError             error
		Timeout                time.Duration
		PlainText              []byte
		CipherText             string
		EncodeTime, DecodeTime time.Time
		DecodeError            error
	}{
		{
			Key:        []byte{0},
			CodecError: ErrInvalidAES,
		},
		{
			Key:         []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			Timeout:     time.Second,
			PlainText:   []byte("Hello, World!"),
			CipherText:  "AAAAAAAAAAAdKAY8ip5Rg52eDtMjh+K9l8a1hzJ8VmWoruZ9B9DeeKM=",
			EncodeTime:  tn,
			DecodeTime:  tn.Add(time.Second * 2),
			DecodeError: ErrExpired,
		},
		{
			Key:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			Timeout:    time.Second * 2,
			PlainText:  []byte("Hello, World!"),
			CipherText: "AAAAAAAAAAAdKAY8ip5Rg52eDtMjh+K9l8a1hzJ8VmWoruZ9B9DeeKM=",
			EncodeTime: tn,
			DecodeTime: tn.Add(time.Second),
		},
		{
			Key:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			Timeout:    time.Second * 2,
			PlainText:  []byte("Hello, World!FooBarBaz"),
			CipherText: "AAAAAAAAAAAdKAY86i3wJ25M3dgYUXdLgC3lE/PdEOaVT/BX/qD976cfqDfq0Hgotmc=",
			EncodeTime: tn,
			DecodeTime: tn.Add(time.Second),
		},
	}
	var (
		ts  [2]time.Time
		buf [1024]byte
	)
	for n, test := range tests {
		ts[0] = test.EncodeTime
		ts[1] = test.DecodeTime
		times = ts[:]
		c, err := NewCodec(test.Key, test.Timeout)
		if err != nil {
			if test.CodecError == nil {
				t.Errorf("test %d: unexpected codec error: %s", n+1, err)
			} else if err != test.CodecError {
				t.Errorf("test %d: got incorrect codec error: %s", n+1, err)
			}
			continue
		} else if test.CodecError != nil {
			t.Errorf("test %d: failed to get expected codec error", n+1)
			continue
		}
		d := c.Encode(test.PlainText, buf[:512:512])
		bd := base64.StdEncoding.EncodeToString(d)
		if bd != test.CipherText {
			t.Errorf("test %d: got incorrect cipher text", n+1)
			continue
		}
		e, err := c.Decode(d, buf[512:512])
		if err != nil {
			if test.DecodeError == nil {
				t.Errorf("test %d: unexpected decode error: %s", n+1, err)
			} else if err != test.DecodeError {
				t.Errorf("test %d: go incorrect decode error: %s", n+1, err)
			}
		} else if test.DecodeError != nil {
			t.Errorf("test %d: failed to get expected decode error", n+1)
		} else if !bytes.Equal(test.PlainText, e) {
			fmt.Println(e)
			t.Errorf("test %d: result does not match plaintext", n+1)
		}
	}

}
