package utils

import "unsafe"

func B2S(b []byte) string {
	size := len(b)
	if size == 0 {
		return ""
	}
	return unsafe.String(&b[0], size)
}

func S2B(s string) (b []byte) {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
