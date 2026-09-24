package pdf

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// grouped writes n with its thousands separated by commas.
func grouped(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// mib writes n, a whole number of mebibytes, as adapters/README.md does.
func mib(n int) string {
	if n%(1<<20) != 0 {
		panic(n)
	}
	return fmt.Sprintf("%d MiB", n>>20)
}

// readmeRow is the row of adapters/README.md's structure bounds table whose
// first cell is label, split into its cells.
func readmeRow(t *testing.T, readme, label string) []string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(readme, "\n") {
		cells := strings.Split(strings.TrimSpace(line), " | ")
		if len(cells) == 3 && strings.TrimPrefix(cells[0], "| ") == label {
			if found != nil {
				t.Fatalf("two rows for %q", label)
			}
			found = cells
		}
	}
	if found == nil {
		t.Fatalf("adapters/README.md has no row for %q", label)
	}
	return found
}

// adapters/README.md states the reader's structure bounds with the values
// the constants hold.
func TestREADMEStatesTheStructureBounds(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	for label, value := range map[string]string{
		"indirect objects read inside another object's read, including stream lengths":                             grouped(maxRefDepth),
		"indirect objects read in one document":                                                                    grouped(maxObjects),
		"references resolving to references":                                                                       grouped(maxRefDepth),
		"the bytes searched for an `endstream` a stream's `/Length` does not locate":                               grouped(endstreamBlock) + " bytes",
		"cross-reference entries, scanned objects or trailers read between two readings of the deadline":           grouped(entriesPerCheck),
		"inspections of a byte of the file made searching for object headers between two readings of the deadline": grouped(scanBytesPerCheck),
		"glyphs shown between two readings of the deadline":                                                        grouped(operatorsPerCheck),
		"fonts held by reference for a document; font resource names held while one page's content is read":        grouped(maxFontCacheEntries) + "; " + grouped(maxFontCacheEntries),
		"arrays and dictionaries nested in one another":                                                            grouped(maxNesting),
		"elements of one array, members of one dictionary":                                                         grouped(maxContainerItems),
		"a name token; a string token; a numeric token":                                                            grouped(maxNameBytes) + " bytes; " + mib(maxStringBytes) + "; " + grouped(maxNumberBytes) + " bytes",
		"objects one object stream declares":                                                                       grouped(maxObjStmObjects),
		"cross-reference sections in the `/Prev` and `/XRefStm` chain":                                             grouped(maxXrefSections),
		"the object numbers one cross-reference section declares":                                                  grouped(maxXrefEntries),
		"objects found while the cross-reference is rebuilt by scanning":                                           grouped(maxScanObjects),
		"page-tree depth; page-tree nodes visited":                                                                 grouped(maxPageTreeDepth) + "; " + grouped(maxPageTreeNodes),
		"operators interpreted on one page, the forms it draws included":                                           grouped(maxOperators),
		"operators interpreted between two readings of the deadline":                                               grouped(operatorsPerCheck),
		"forms drawn within forms":                                                                                 grouped(maxFormDepth),
		"the operand stack":                                                                                        grouped(maxOperands),
		"graphics states saved and not restored":                                                                   grouped(maxGraphicsStates),
		"one inline image's dictionary; its data":                                                                  grouped(2*maxOperands) + " objects; " + mib(maxInlineImageBytes),
		"a page's content streams, concatenated":                                                                   mib(maxContentBytes),
		"characters the glyphs shown on one page map to, the forms it draws included":                              grouped(maxCharacters),
		"width entries one font's `/W` declares":                                                                   grouped(maxCIDWidths),
		"the CID a `/W` entry names; the CIDs one `/W` range spans":                                                "below " + grouped(maxWidthCID) + "; " + grouped(maxWidthRange),
		"mappings one CMap holds":                                                                                  grouped(maxCMapEntries),
		"codespace ranges one CMap declares":                                                                       grouped(maxCodespaces),
		"width entries and CMap mappings of all of a document's fonts together":                                    grouped(maxFontEntries),
		"the codes one `bfrange` or `cidrange` spans":                                                              grouped(maxCMapRange),
		"a `bfchar` or `bfrange` destination string":                                                               grouped(maxCMapDestinationBytes) + " bytes",
	} {
		if row := readmeRow(t, readme, label); row[1] != value {
			t.Errorf("%s: adapters/README.md says %q, the reader holds %q", label, row[1], value)
		}
	}
}
