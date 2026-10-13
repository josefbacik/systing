// The workload of systing-go-profile's end-to-end check: a known heap,
// lock and channel waits (with both profiles switched on), parked
// goroutines, a pprof port, and Go's flight recorder, so every profile can be
// read out of memory and compared with what the program itself serves.
//
// It prints "port <port> pid <pid>" once listening. GET /flight?out=<path>
// writes the flight recorder's window through the program's own WriteTo.
package main

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/trace"
	"sync"
	"time"
)

var (
	keep [][]byte
	sink []byte
	mu   sync.Mutex
)

//go:noinline
func retainBig() { keep = append(keep, make([]byte, 1<<20)) }

//go:noinline
func retainSmall() { keep = append(keep, make([]byte, 4096)) }

//go:noinline
func churn(n int) []byte { return make([]byte, n) }

//go:noinline
func holdLock() {
	mu.Lock()
	time.Sleep(2 * time.Millisecond)
	mu.Unlock()
}

//go:noinline
func producer(c chan<- int) {
	for i := 0; ; i++ {
		c <- i
	}
}

//go:noinline
func consumer(c <-chan int) {
	for range c {
		time.Sleep(time.Millisecond)
	}
}

//go:noinline
func parked(c chan int) { <-c }

func main() {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	for i := 0; i < 64; i++ {
		retainBig()
	}
	for i := 0; i < 20000; i++ {
		retainSmall()
	}
	// About 70 MB/s of garbage: a collection every few seconds.
	go func() {
		for {
			for i := 0; i < 10; i++ {
				sink = churn(64 << 10)
				sink = churn(512)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	for i := 0; i < 4; i++ {
		go func() {
			for {
				holdLock()
			}
		}()
	}
	c := make(chan int)
	go producer(c)
	go consumer(c)
	never := make(chan int)
	for i := 0; i < 1000; i++ {
		go parked(never)
	}

	fr := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 3 * time.Second, MaxBytes: 256 << 20})
	if err := fr.Start(); err != nil {
		panic(err)
	}
	http.HandleFunc("/flight", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Create(r.URL.Query().Get("out"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		if _, err := fr.WriteTo(f); err != nil {
			http.Error(w, err.Error(), 500)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("port %d pid %d\n", ln.Addr().(*net.TCPAddr).Port, os.Getpid())
	http.Serve(ln, nil)
}
