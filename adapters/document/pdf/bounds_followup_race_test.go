//go:build race

package pdf

// boundsInstrumented says whether the allocations this test binary makes are
// the reader's own. The race detector adds its own to every allocation, so a
// measurement taken under it is not what the reader retains.
const boundsInstrumented = true

// raceFactor is what every wall-clock allowance in these tests is multiplied
// by. It is the race detector's documented cost, which is two to twenty times
// the execution time, and it says nothing about the reader: what an allowance
// bounds is work that grows with the file rather than with the machine, and
// off the detector the allowances are the ones written.
const raceFactor = 4
