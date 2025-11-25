package common

import (
	"sync"
)

type locker struct {
	mu  sync.Mutex
	ref int
}

type KeyLocker[K comparable] struct {
	mu sync.Mutex
	m  map[K]*locker
}

func (kl *KeyLocker[K]) Lock(key K) (l *locker, isNew bool) {
	kl.mu.Lock()
	if kl.m == nil {
		kl.m = make(map[K]*locker)
	}
	l, ok := kl.m[key]
	if !ok {
		l = &locker{ref: 1}
		kl.m[key] = l
	} else {
		l.ref++
	}
	kl.mu.Unlock()

	l.mu.Lock()
	return l, !ok
}

func (kl *KeyLocker[K]) Unlock(key K, l *locker) {
	l.mu.Unlock()

	kl.mu.Lock()
	l.ref--
	if l.ref == 0 {
		delete(kl.m, key)
	}
	kl.mu.Unlock()
}
