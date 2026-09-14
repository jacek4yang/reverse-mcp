// CTF-grade test fixture #3 (Go): goroutine-driven key agreement + reflection
// strings. Challenges: Go runtime bloat, goroutine interleaving, interface
// dispatch, string-to-[]byte conversions, defer-heavy cleanup, and a
// split-key check across two goroutines synchronized via channels.

package main

import (
	"fmt"
	"os"
	"sync"
)

// splitKey derives two halves of the final key from a seed, in parallel.
func splitKey(seed uint64, out chan<- uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	hi := seed >> 32
	lo := seed & 0xFFFFFFFF

	hi = hi*0x9E3779B97F4A7C15 ^ (hi >> 17)
	lo = (lo ^ 0xDEADBEEF) * 0xBF58476D1CE4E5B9

	// fold hi into lo again through a channel handshake
	mid := make(chan uint64, 1)
	go func() {
		mid <- hi ^ lo
	}()
	folded := <-mid
	out <- folded ^ (lo << 13) ^ (hi >> 7)
}

// obfuscatedCheck: byte-level comparison against a stack-built target.
func check(final uint64) bool {
	// target = 0x5EED_C0DE_1337_4242 XOR-folded twice
	t := uint64(0x5EEDC0DE13374242)
	t ^= t >> 33
	t *= 0xFF51AFD7ED558CCD
	t ^= t >> 33
	return final == t
}

type verdict string

func (v verdict) String() string { return string(v) }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ctf_go <seed>")
		os.Exit(2)
	}
	var seed uint64
	if _, err := fmt.Sscanf(os.Args[1], "%d", &seed); err != nil {
		fmt.Fprintln(os.Stderr, "bad seed")
		os.Exit(3)
	}

	out := make(chan uint64, 2)
	var wg sync.WaitGroup
	wg.Add(1)
	go splitKey(seed, out, &wg)
	wg.Wait()
	final := <-out

	var result verdict
	if check(final) {
		result = verdict("flag{go_r0ut1n3_k3y_" + fmt.Sprintf("%x", final) + "}")
	} else {
		result = "denied"
	}
	fmt.Println(result.String())
	if result != "flag{go_r0ut1n3_k3y_" {
		// keep the failure path alive: defer order matters in analysis
		defer fmt.Fprintln(os.Stderr, "better luck next time")
	}
}
