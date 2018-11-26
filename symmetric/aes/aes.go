package aes

import (
	"crypto/cipher"
	"crypto_util/handle"
	"crypto/aes"
)

//加密
func EncryptAES(src,key,iv []byte) []byte {
	block,err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	src = handle.PaddingText(src,block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block,iv)
	dst := make([]byte,len(src))
	blockMode.CryptBlocks(dst,src)
	return dst
}

//解密
func DecryptAES(src,key,iv []byte) []byte {
	block,err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	} 

	blockMode := cipher.NewCBCDecrypter(block,iv)
	dst := make([]byte,len(src))
	blockMode.CryptBlocks(dst,src)

	newText := handle.UnPaddingText(dst)
	return newText
}