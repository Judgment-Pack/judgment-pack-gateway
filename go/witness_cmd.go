package main

// `gateway witness verify`: a witness's log checked offline, by anyone
// holding a copy of it and the witness's public key (docs/adr/0013-checkpoint-
// witness.md §4, "How the witness is itself checked").

import (
	"encoding/json"
	"fmt"
	"io"
)

const witnessUsage = "usage: gateway witness verify --log <file> --public-key <file> [--marks <file>]"

func cmdWitness(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(stderr, witnessUsage)
		return 2
	}
	flags := map[string]string{}
	for rest := args[1:]; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		if (name != "--log" && name != "--public-key" && name != "--marks") || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, witnessUsage)
			return 2
		}
		if _, given := flags[name]; given {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", name, witnessUsage)
			return 2
		}
		flags[name] = rest[1]
	}
	if flags["--log"] == "" || flags["--public-key"] == "" {
		fmt.Fprintln(stderr, witnessUsage)
		return 2
	}
	out, err := witnessVerify(flags["--log"], flags["--public-key"], flags["--marks"])
	if err != nil {
		// no verdict could be reached
		fmt.Fprintln(stderr, "witness verify:", err)
		return 1
	}
	stdout.Write(append(out, '\n'))
	return 0
}

// witnessVerifyReport is the verdict, as `gateway verify` gives its own in
// its JSON (SPEC.md §5a.2): ok exactly when the checks found nothing. With
// the marks, outcome is what the witness's start-up would do with these two
// files; without them, null.
type witnessVerifyReport struct {
	OK         bool             `json:"ok"`
	Findings   []witnessFinding `json:"findings"`
	Outcome    *string          `json:"outcome"`
	Statements int64            `json:"statements"`
}

// witnessVerify applies the witness's start-up checks to a copy of its log,
// all but the registrations: every complete line a statement in the bytes
// the witness writes, verifying under the key given; each trail's chain
// from index 0, contiguous and linked, by the chain rule; and the log
// ending cleanly. Given the marks, also that the log reaches every mark and
// that no statement but the log's last is unmarked, with the outcome the
// three rules of recovery give. A key the key rule refuses is answered as a
// reader answers it, {"refused": <reason>}, before the log is read.
//
// That shows a copy is internally consistent. It does not authenticate
// registrations, show that every trail or statement was kept, or show that
// the copy is the log the witness serves now.
func witnessVerify(logPath, keyPath, marksPath string) ([]byte, error) {
	key, err := readWitnessKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	if refusal := witnessKeyRefusal(key); refusal != "" {
		return json.Marshal(map[string]string{"refused": refusal})
	}
	log, err := openRegular(logPath)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	in := witnessInput{log: log}
	if marksPath != "" {
		marks, err := openRegular(marksPath)
		if err != nil {
			return nil, err
		}
		defer marks.Close()
		in.marks, in.marksChecked = marks, true
	}
	j, err := judgeWitness(in, key)
	if err != nil {
		return nil, err
	}
	report := witnessVerifyReport{OK: len(j.findings) == 0, Findings: j.findings.list(), Statements: j.statements}
	if marksPath != "" {
		report.Outcome = &j.outcome
	}
	return json.Marshal(report)
}
