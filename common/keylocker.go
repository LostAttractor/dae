package common

import (
	"sync"
	"sync/atomic"
)

type locker struct {
	mu  sync.Mutex
	ref atomic.Uint32
}

type KeyLocker[K comparable] struct {
	m sync.Map // map[K]*locker
}

func (kl *KeyLocker[K]) Lock(key K) *locker {
	lRaw, _ := kl.m.LoadOrStore(key, new(locker))
	l := lRaw.(*locker)
	l.ref.Add(1)
	l.mu.Lock()
	return l
}

func (kl *KeyLocker[K]) Unlock(key K, l *locker) {
	l.mu.Unlock()
	if l.ref.Add(^uint32(0)) == 0 {
		kl.m.Delete(key)
	}
}
