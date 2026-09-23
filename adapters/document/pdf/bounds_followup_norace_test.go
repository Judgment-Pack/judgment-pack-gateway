//go:build !race

package pdf

// boundsInstrumented says whether the allocations this test binary makes are
// the reader's own. The race detector adds its own to every allocation, so a
// measurement taken under it is not what the reader retains.
const boundsInstrumented = false

// raceFactor is what every wall-clock allowance in these tests is multiplied
// by. Nothing instruments this binary, so the allowances are the ones written.
const raceFactor = 1
