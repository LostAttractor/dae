package fastrand

import (
	"crypto/rand"
	mathrand "math/rand/v2"
)

func Intn(n int) int                   { return mathrand.IntN(n) }
func Int() int                         { return mathrand.Int() }
func Int31n(n int32) int32             { return mathrand.Int32N(n) }
func Int63n(n int64) int64             { return mathrand.Int64N(n) }
func Uint32() uint32                   { return mathrand.Uint32() }
func Float64() float64                 { return mathrand.Float64() }
func Read(p []byte) (n int, err error) { return rand.Read(p) }
