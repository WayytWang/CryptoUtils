package handle

import (
	"bytes"
)

//填充最后一个分组
func PaddingText(src []byte, blockSize int) []byte{
	//1.填充长度和填充内容
	padding := blockSize - len(src)%blockSize

	//2.创建待补充的内容切片
	paddingText := bytes.Repeat([]byte{byte(padding)},padding)

	//3.将paddingText和src合并
	newText := append(src,paddingText...)
	return newText
}

//删除填充的内容
func UnPaddingText(src []byte) []byte {
	length := len(src)

	//1.取出最后一个字符的整型值
	number := int(src[length - 1])

	//2.删除number个number
	newText := src[:length-number]
	return newText
}