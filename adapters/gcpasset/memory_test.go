package gcpasset

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"time"
)

// hostile answers of about n bytes, each a shape that costs the reading
// the most for its size: many small variables whose values are dropped,
// many tiny assets, wide objects of members not projected, and policies of
// many members under count-users.
func hostile(shape string, n int) []byte {
	var b strings.Builder
	b.WriteString(`{"assets":[`)
	first := true
	for b.Len() < n {
		if !first {
			b.WriteByte(',')
		}
		first = false
		switch shape {
		case "env":
			b.WriteString(`{"name":"s","assetType":"run.googleapis.com/Service","resource":{"data":{"template":{"containers":[{"name":"c","env":[`)
			for i := 0; i < 200; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`{"name":"V","value":"x"}`)
			}
			b.WriteString(`]}]}}}}`)
		case "tiny":
			b.WriteString(`{"name":"a","assetType":"storage.googleapis.com/Bucket"}`)
		case "wide":
			b.WriteString(`{"name":"w","assetType":"storage.googleapis.com/Bucket","resource":{"data":{`)
			for i := 0; i < 500; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `"m%d":[0]`, i)
			}
			b.WriteString(`}}}`)
		case "members":
			b.WriteString(`{"name":"p","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[{"role":"roles/storage.objectViewer","members":[`)
			for i := 0; i < 500; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`"user:u@x"`)
			}
			b.WriteString(`]}]}}`)
		}
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

// allocated is what projecting body allocates, in bytes, and the most the
// heap's objects grew by while it ran, sampled every millisecond.
func allocated(t *testing.T, s *source, body []byte, req Request) (total, peak uint64) {
	t.Helper()
	runtime.GC()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	base := sample[0].Value.Uint64()
	done, highest := make(chan struct{}), make(chan uint64)
	go func() {
		most := uint64(0)
		probe := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			metrics.Read(probe)
			if v := probe[0].Value.Uint64(); v > most {
				most = v
			}
			select {
			case <-done:
				highest <- most
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := s.projectPage(body, req, testEmail); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	close(done)
	most := <-highest
	if most > base {
		peak = most - base
	}
	return after.TotalAlloc - before.TotalAlloc, peak
}

// The reading is linear in the answer: for each hostile shape, twice the
// answer costs about twice the allocation, and the worst case at the
// default answer bound is stated. TotalAlloc counts every allocation made,
// freed or not, so it bounds the peak from above.
func TestMemoryIsLinearInTheAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("measures allocation over 8 MiB answers")
	}
	s := &source{cfg: Config{Members: MembersCountUsers}}
	worst, worstPeak := 0.0, uint64(0)
	for _, shape := range []string{"env", "tiny", "wide", "members"} {
		req := Request{ContentType: ContentResource, AssetTypes: ServedAssetTypes()}
		if shape == "members" {
			req.ContentType = ContentIAMPolicy
		}
		half, whole := hostile(shape, DefaultMaxAnswer/2), hostile(shape, DefaultMaxAnswer)
		a, _ := allocated(t, s, half, req)
		b, peak := allocated(t, s, whole, req)
		ratio := float64(b) / float64(a)
		perByte := float64(b) / float64(len(whole))
		t.Logf("%s: %d bytes allocate %d (%.1f per byte), the heap's peak %d MiB above its start; twice the answer, %.2f times the allocation", shape, len(whole), b, perByte, peak>>20, ratio)
		if ratio > 2.5 {
			t.Errorf("%s: twice the answer allocates %.2f times as much", shape, ratio)
		}
		if perByte > worst {
			worst = perByte
		}
		if peak > worstPeak {
			worstPeak = peak
		}
	}
	if worst > 160 {
		t.Errorf("the worst shape allocates %.1f bytes per answer byte", worst)
	}
	if worstPeak > 48*DefaultMaxAnswer {
		t.Errorf("the worst shape's heap peaked %d MiB above its start", worstPeak>>20)
	}
	t.Logf("worst case at the default bound of %d MiB: %.1f bytes allocated per answer byte (%.0f MiB in all), the heap's peak %d MiB above its start", DefaultMaxAnswer>>20, worst, worst*DefaultMaxAnswer/(1<<20), worstPeak>>20)
}
