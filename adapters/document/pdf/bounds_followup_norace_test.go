//go:build !race

package pdf

// boundsInstrumented says whether the allocations this test binary makes are
// the reader's own. The race detector adds its own to every allocation, so a
// measurement taken under it is not what the reader retains.
const boundsInstrumented = false
