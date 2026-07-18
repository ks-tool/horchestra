package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// NewUIDv4 returns a random RFC 4122 version-4 UUID string.
func NewUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewUIDv7 returns an RFC 9562 version-7 UUID string. Its first 48 bits encode the
// current Unix time in milliseconds, so uidTime can recover the creation time
// from the uid alone.
func NewUIDv7() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	ms := uint64(time.Now().UnixMilli())
	b[0], b[1], b[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
	b[3], b[4], b[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TimeFromUUIDv7 recovers the creation time a version-7 UUID encodes in its first 48
// bits (Unix milliseconds); it returns the zero time for a non-v7 or unparseable
// uid.
func TimeFromUUIDv7(uid string) time.Time {
	b, err := hex.DecodeString(strings.ReplaceAll(uid, "-", ""))
	if err != nil || len(b) != 16 || b[6]>>4 != 7 {
		return time.Time{}
	}
	ms := int64(b[0])<<40 | int64(b[1])<<32 | int64(b[2])<<24 | int64(b[3])<<16 | int64(b[4])<<8 | int64(b[5])
	return time.UnixMilli(ms).UTC()
}
