package hash

import (
	"encoding/hex"
	"crypto/md5"
)

func GetMd5Str(src []byte) string {
	//1.创建hash接口
	myhash := md5.New()

	//2.添加数据
	myhash.Write(src)

	//3.计算结果
	res := myhash.Sum(nil)
	resStr := hex.EncodeToString(res[:])
	return resStr
}