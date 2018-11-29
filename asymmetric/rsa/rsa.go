package rsa

import (
	"crypto/rand"
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
)

//生成密钥对
func RsaGenerate(bits int) error {
	//1.生成私钥
	privateKey,err := rsa.GenerateKey(rand.Reader,bits)
	if err != nil {
		return err
	}

	//2.通过x509标准将得到的rsa私钥序列化为ASN.1 的DER编码字符串
	privStream := x509.MarshalPKCS1PrivateKey(privateKey)

	//3.将私钥字符串设置到pem格式块中
	block := pem.Block{
		Type:"my privateKey",
		Bytes:privStream,
	}

	//4.通过pem将设置好的数据进行解码，并写入磁盘文件中
	privFile,err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer privFile.Close()

	err = pem.Encode(privFile,&block)
	if err != nil {
		return err
	}

	//5.从得到的私钥中获取到公钥
	publicKey := privateKey.PublicKey

	//6.通过x509标准将得到的rsa公钥序列化为ASN.1 的DER编码字符串
	publicStream,err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}

	//7.将公钥字符串设置到pem格式块中
	block = pem.Block{
		Type:"my publicKey", 
		Bytes:publicStream,
	}

	//8.通过pem将设置好的数据进行解码，并写入磁盘文件中
	pubFile,err := os.Create("public.pem")
	if err != nil {
		return err
	}

	err = pem.Encode(pubFile,&block)
	if err != nil {
		return err
	}

	return nil
}

//根据.pem文件得到公钥
func GetPublicKey(pathName string)(publickey *rsa.PublicKey,err error) {
	file,err := os.Open(pathName)
	if err != nil {
		return
	}
	defer file.Close()

	info,err := file.Stat()
	if err != nil {
		return
	}
	recvBuf := make([]byte,info.Size())
	_,err = file.Read(recvBuf)
	if err != nil {
		return
	}

	block,_ := pem.Decode(recvBuf)

	publicInter,err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	publickey = publicInter.(*rsa.PublicKey)
	return publickey,nil
}

func GetPrivateKey(pathName string)(privateKey *rsa.PrivateKey,err error) {
	file,err := os.Open(pathName)
	if err != nil {
		return
	}
	defer file.Close()

	info,err := file.Stat()
	if err != nil {
		return
	}
	recvBuf := make([]byte,info.Size())
	_,err = file.Read(recvBuf)
	if err != nil {
		return
	}

	block,_ := pem.Decode(recvBuf)
	privateKey,err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	return
}

//使用公钥加密
func EncryptRSAPub(src []byte,pathName string)(msg []byte,err error) {
	pubKey,err := GetPublicKey(pathName)
	if err != nil {
		return
	}

	msg,err = rsa.EncryptPKCS1v15(rand.Reader,pubKey,src)
	if err != nil {
		return 
	}
	return 

}
//使用私钥解密
func DecryptRSAPrivate(src []byte,pathName string) (msg []byte,err error) {
	privateKey,err := GetPrivateKey(pathName)
	if err != nil {
		return
	}
	
	msg,err = rsa.DecryptPKCS1v15(rand.Reader,privateKey,src)
	if err != nil {
		return 
	}
	return 
}




