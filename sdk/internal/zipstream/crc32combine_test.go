// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"hash/crc32"
	"math/rand"
	"testing"
)

func TestCRC32CombineIEEE_Basic(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	a := make([]byte, 1024)
	b := make([]byte, 2048)
	rng.Read(a)
	rng.Read(b)

	crcA := crc32.ChecksumIEEE(a)
	crcB := crc32.ChecksumIEEE(b)
	combined := CRC32CombineIEEE(crcA, crcB, int64(len(b)))

	all := append(append([]byte{}, a...), b...)
	want := crc32.ChecksumIEEE(all)

	if combined != want {
		t.Fatalf("combined CRC mismatch: got %08x want %08x", combined, want)
	}
}

func TestCRC32CombineIEEE_MultiChunks(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	chunks := make([][]byte, 10)
	for i := range chunks {
		n := 1 + rng.Intn(8192)
		chunks[i] = make([]byte, n)
		rng.Read(chunks[i])
	}

	// Combine sequentially
	var total uint32
	var init bool
	for _, c := range chunks {
		crc := crc32.ChecksumIEEE(c)
		if !init {
			total = crc
			init = true
		} else {
			total = CRC32CombineIEEE(total, crc, int64(len(c)))
		}
	}

	// Compute directly over concatenation
	var all []byte
	for _, c := range chunks {
		all = append(all, c...)
	}
	want := crc32.ChecksumIEEE(all)

	if total != want {
		t.Fatalf("multi-chunk combined CRC mismatch: got %08x want %08x", total, want)
	}
}

func TestCRC32CombineIEEE_Associativity(t *testing.T) {
	a := []byte("alpha")
	b := []byte("beta")
	c := []byte("charlie")

	ca := crc32.ChecksumIEEE(a)
	cb := crc32.ChecksumIEEE(b)
	cc := crc32.ChecksumIEEE(c)

	left := CRC32CombineIEEE(ca, CRC32CombineIEEE(cb, cc, int64(len(c))), int64(len(b)+len(c)))
	right := CRC32CombineIEEE(CRC32CombineIEEE(ca, cb, int64(len(b))), cc, int64(len(c)))

	if left != right {
		t.Fatalf("associativity failed: left %08x right %08x", left, right)
	}
}

func TestCRC32CombineIEEE_ZeroLength(t *testing.T) {
	a := []byte("data")
	ca := crc32.ChecksumIEEE(a)
	// Combining with zero-length second part should be identity
	got := CRC32CombineIEEE(ca, 0, 0)
	if got != ca {
		t.Fatalf("zero-length combine mismatch: got %08x want %08x", got, ca)
	}
}
