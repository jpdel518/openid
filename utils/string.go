package utils

import "math/rand"

func RandomString(n int) string {
	var letterBytes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

	buf := make([]rune, n)
	for i := range buf {
		buf[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	return string(buf)
}
