package main
import (
	"crypto_util/asymmetric/rsa"
	"crypto_util/symmetric/des"
	"crypto_util/symmetric/aes"
	"crypto_util/symmetric/tri_des"
	"crypto_util/asymmetric/sign"
	"crypto_util/hash"
	"fmt"
)

func main() {
	//Aes_Test()
	//Des_Test()
	//TriDes_Test()
	//RsaGenerate_Test()
	//PubEncrypt_Test()
	//MD5_Test()
	//SHA256_Test()
	Sign_Test()
}

//测试des
func Des_Test() {
	fmt.Println("===== des加解密 =====")
	src := []byte("des是一种过时的加密方式")
	key := []byte("12345678")
	iv := []byte("12345678")

	str := des.EncryptDES(src,key,iv)  
	str = des.DecryptDES(str,key,iv)
	fmt.Println("解密之后的结果是：",string(src))
}

//测试3des
func TriDes_Test() {
	fmt.Println("===== 3des加解密 =====")
	src := []byte("3des是一种过时的加密方式")
	key := []byte("123456788765432112563478")
	iv := []byte("12345678")

	str := tri_des.Encrypt3DES(src,key,iv)  
	str = tri_des.Decrypt3DES(str,key,iv)
	fmt.Println("解密之后的结果是：",string(src))
}

//测试aes
func Aes_Test() {
	fmt.Println("===== aes加解密 =====")
	src := []byte("aes是现在最常用的对称加密方式")
	key := []byte("1234567887654321")
	iv := []byte("1234567887654321")

	str := aes.EncryptAES(src,key,iv)  
	str = aes.DecryptAES(str,key,iv)
	fmt.Println("解密之后的结果是：",string(src))
}

//测试rsa生成密钥对
func RsaGenerate_Test(){
	fmt.Println("===== rsa生成密钥对 =====")
	err := rsa.RsaGenerate(4096)
	if err != nil {
		fmt.Println("错误信息：",err)
		return 
	}
	fmt.Println("成功")
}

//测试公钥加密私钥解密
func PubEncrypt_Test() {
	fmt.Println("===== 公钥加密私钥解密 =====")
	src := []byte("来测试公钥加密私钥是否能解密")
	msg,err := rsa.EncryptRSAPub(src,"public.pem")
	if err != nil {
		fmt.Println("错误信息：",err)
	}

	data,err := rsa.DecryptRSAPrivate(msg,"private.pem")
	if err != nil {
		fmt.Println("错误信息：",err)
	}

	fmt.Println("解密结果:",string(data))
}

//测试签名校验
func Sign_Test(){
	fmt.Println("===== 签名校验 =====")
	src := []byte("测试签名校验")

	//加密明文
	msg,err := rsa.EncryptRSAPub(src,"public.pem")
	if err != nil {
		fmt.Println("错误信息：",err)
	}

	//签名
	signature,err := sign.Signature(src,"private.pem")
	if err != nil {
		fmt.Println("错误信息：",err)
	}

	//验证签名
	err = sign.ValidateSign(msg,signature,"private.pem","public.pem")
	if err != nil {
		fmt.Println("错误信息：",err)
	}

	fmt.Println("校验成功")
}

//测试md5算hash
func MD5_Test() {
	fmt.Println("===== md5hash运算 =====")
	src := []byte("md5运算测试")
	res := hash.GetMd5Str(src)
	fmt.Println("hash：",res)
}

//测试sha256算hash
func SHA256_Test() {
	fmt.Println("===== sha256hash运算 =====")
	src := []byte("sha256运算测试")
	res := hash.GetSHA256Str(src)
	fmt.Println("hash：",res)
}