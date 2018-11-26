package des

import (
	"crypto/cipher"
	"crypto_util/handle"
	"crypto/des"
)

//使用des加密
func EncryptDES(src,key,iv []byte) []byte{
	block,err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	src = handle.PaddingText(src,block.BlockSize())

	blockMode := cipher.NewCBCEncrypter(block,iv)
	dst := make([]byte,len(src))
	blockMode.CryptBlocks(dst,src)
	return dst
}

//使用des解密
func DecryptDES(src,key,iv []byte) []byte{
	block,err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockMode := cipher.NewCBCDecrypter(block,iv)
	dst := make([]byte,len(src))
	blockMode.CryptBlocks(dst,src)

	newText := handle.UnPaddingText(dst)
	return newText
}