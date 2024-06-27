package ternary

func BV[T any](exp bool, trueVar T, falseVar T) T {
	if exp {
		return trueVar
	} else {
		return falseVar
	}
}
