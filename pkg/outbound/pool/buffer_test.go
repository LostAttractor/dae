package pool

import "testing"

func TestBufferCapacityMatchesAllocation(t *testing.T) {
	for _, size := range []int{0, 1, 2, 3, 1514, 32768, 32769, 65535, maxsize, maxsize + 1} {
		b := GetBuffer(size)
		if cap(b) != BufferCapacity(size) {
			t.Fatalf("size %d: capacity %d, reserved %d", size, cap(b), BufferCapacity(size))
		}
		PutBuffer(b)
	}
}
