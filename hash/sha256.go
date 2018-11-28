package hash

import (
	"encoding/hex"
	"crypto/sha256"
)

func GetSHA256Str(src []byte) string{
	myhash := sha256.New()
	myhash.Write(src)
	res := myhash.Sum(nil)
	resStr := hex.EncodeToString(res[:])
	return resStr
}