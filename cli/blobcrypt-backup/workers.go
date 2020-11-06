package main

import (
	"runtime"
	"sync"
)

// RunWorkers starts and waits for a pool of n workers receiving from c, calling fn on each input.
// Returns an unordered slice of all non-nil return values from fn.
// When n == 0, a number of workers is chosen that does not exceed the number of available CPUs.
func RunWorkers(n int, c chan interface{}, fn func(interface{}) interface{}) []interface{} {
	var results []interface{}
	var mutex sync.Mutex
	var group sync.WaitGroup

	if n == 0 {
		n = runtime.NumCPU()
		// Leave some headroom on larger machines when possible.
		if n > 3 {
			n -= n / 3
		}
	}

	// Start a number of workers which will exit when the context does.
	for i := 0; i < n; i++ {
		group.Add(1)
		go func() {
			defer group.Done()

			for input := range c {
				switch val := fn(input).(type) {
				case nil:
					// Do not collect nil values
				default:
					mutex.Lock()
					results = append(results, val)
					mutex.Unlock()
				}
			}
		}()
	}
	group.Wait()
	return results
}
