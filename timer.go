// Copyright 2014-2015 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package mnet

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"
)

const (
	stateSignaled = uint32(1 << iota)
	stateActive
)

// timer object for clients
type timer struct {
	// public data to be set
	*sync.Cond

	expirationNS int64
	state        uint32
}

// Has the timer been signaled
func (t *timer) Signaled() bool {
	return stateSignaled == (atomic.LoadUint32(&t.state) & stateSignaled)
}

// Is the timer active
func (t *timer) Active() bool {
	return stateActive == (atomic.LoadUint32(&t.state) & stateActive)
}

type timerHeap []*timer

type timerQueue struct {
	sync.Cond
	t       *time.Timer
	h       timerHeap
	now     int64
	running bool
}

// Create a new timer queue
func newTimerQueue() *timerQueue {
	tq := &timerQueue{
		Cond:    sync.Cond{L: new(sync.Mutex)},
		t:       time.NewTimer(0),
		now:     time.Now().UnixNano(),
		running: true,
	}
	heap.Init(&tq.h)

	closeTimer := make(chan struct{})
	go tq.proc(closeTimer)
	go tq.timeoutProc(closeTimer)
	return tq
}

// Close the timer queue, freeing up any resources allocated
func (tq *timerQueue) Close() {
	tq.L.Lock()
	tq.running = false
	tq.L.Unlock()
	tq.Signal()
}

// Get the most recent time polled by the timer queue
func (tq *timerQueue) Now() time.Time {
	return time.Unix(0, tq.now)
}

// Starts timer `t` for the specified duration. While the timer
// is waiting, t.Active() will return true. If the timer's
// duration elapses without a call to `StopTimer` the condition
// variable t.Cond will be signaled. In addition, t.Active() will
// return false and t.Signaled() will return true.
func (tq *timerQueue) StartTimer(t *timer, d time.Duration) {
	if 0 != (atomic.LoadUint32(&t.state) & stateActive) {
		panic("timer is already in a pool")
	}
	if t.Cond == nil {
		panic("timer does not have a valid condition variable")
	}

	t.state = stateActive

	tq.L.Lock()
	tq.now = time.Now().UnixNano()
	t.expirationNS = tq.now + int64(d)
	heap.Push(&tq.h, t)
	front := (tq.h[0] == t)
	tq.L.Unlock()

	// if this timer expires before existing timers, signal the proc
	if front {
		tq.Signal()
	}
}

// Stops an active timer. After this call, t.Active() will return false
// and t.Signaled() will return false
func (tq *timerQueue) StopTimer(t *timer) {
	if 0 != (atomic.LoadUint32(&t.state) & stateActive) {
		tq.L.Lock()
		for ii, nn := 0, tq.h.Len(); ii < nn; ii++ {
			if tq.h[ii] == t {
				heap.Remove(&tq.h, ii)
				break
			}
		}
		tq.L.Unlock()
	}

	t.state = 0
}

func (tq *timerQueue) timeoutProc(closed <-chan struct{}) {
	// ready dummy value from timer creation
	<-tq.t.C
	for range tq.t.C {
		tq.Cond.Signal()

		select {
		case <-closed:
			return
		default:
		}
	}
}

func (tq *timerQueue) proc(closeTimer chan<- struct{}) {
	tq.L.Lock()
	defer tq.L.Unlock()

	defer close(closeTimer)

	for tq.running {

		// wait for there to be timers in the queue
		for len(tq.h) == 0 {
			tq.now = time.Now().UnixNano()
			tq.Wait()
		}

		// need to sleep
		tq.now = time.Now().UnixNano()
		if duration := time.Duration(tq.h[0].expirationNS - tq.now); duration > 0 {
			tq.t.Reset(duration * time.Nanosecond)
			tq.Wait()
			continue
		}

		// expire all timers
		cnt := 0
		for ; len(tq.h) > 0; cnt++ {
			t := tq.h[0]
			if exp, st := t.expirationNS, atomic.LoadUint32(&t.state); exp > tq.now && 0 != (st&stateActive) {
				break
			}

			heap.Pop(&tq.h)

			var st uint32
			for {
				st = t.state
				if st == stateActive {
					if atomic.CompareAndSwapUint32(&t.state, st, stateSignaled) {
						break
					}
				}
			}

			if st == stateActive {
				t.Cond.Signal()
			}
		}
	}
}

// timerHeap heap.Interface implementation

func (h timerHeap) Len() int {
	return len(h)
}

func (h timerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h timerHeap) Less(i, j int) bool {
	return h[i].expirationNS < h[j].expirationNS
}

func (h *timerHeap) Push(x interface{}) {
	*h = append(*h, x.(*timer))
}

func (h *timerHeap) Pop() interface{} {
	n := len(*h) - 1
	x := (*h)[n]
	*h = (*h)[:n]
	return x
}
