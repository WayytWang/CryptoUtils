package sign

import (
	"crypto/rand"
	r "crypto_util/asymmetric/rsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto"

)

//src : 明文
//pathName : 私钥地址
func Signature(src []byte,pathName string)(sign []byte,err error) {
	//1.对明文做信息摘要
	myhash := sha256.New()
	myhash.Write(src)
	digest := myhash.Sum(nil) 
	
	//2.取出私钥
	privateKey,err := r.GetPrivateKey(pathName)
	if err != nil {
		return
	}

	//3.对信息摘要签名
	sign,err = rsa.SignPKCS1v15(rand.Reader,privateKey,crypto.SHA256,digest)
	if err != nil {
		return
	}
	return
}

//校验
func ValidateSign(src,sign []byte,privatePath,senderPubPath string)(err error) {
	//1.对接受的密文解密
	msg,err := r.DecryptRSAPrivate(src,privatePath)
	if err != nil {
		return
	}

	//2.对明文求hash值
	myhash := sha256.New()
	myhash.Write(msg)
	res := myhash.Sum(nil)

	//func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) (err error)
	//2.签名验证
	publicKey,err := r.GetPublicKey(senderPubPath)
	if err != nil {
		return
	}
	err = rsa.VerifyPKCS1v15(publicKey,crypto.SHA256,res,sign)
	if err != nil {
		return
	}

	return
}