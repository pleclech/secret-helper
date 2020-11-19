package cleanup

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var e chan int

var wg sync.WaitGroup

type trapFn func()

func init() {
	e = make(chan int, 1)
}

func Exit(code int) {
	if e != nil {
		e <- code
	}
	wg.Wait()
	if e != nil {
		close(e)
		e = nil
	}
	os.Exit(code)
}

func TrapError(fn func() error) trapFn {
	return Trap(func() {
		fn()
	})
}

func Trap(fn trapFn) trapFn {
	wg.Add(1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGSEGV, syscall.SIGTERM, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)

	d := make(chan struct{}, 1)

	ret := func() {
		fn()
		wg.Done()
		close(d)
	}

	go func() {
		defer func() {
			wg.Wait()
			if c != nil {
				close(c)
				os.Exit(1)
			}
		}()

		select {
		case <-c:
			ret()
			break
		case ec := <-e:
			ret()
			e <- ec
			break
		case <-d:
			c = nil
			break
		}
	}()

	return ret
}
