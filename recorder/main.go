package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  recorder verify <ledger.jsonl>            re-check a ledger's hash chain")
	fmt.Fprintln(os.Stderr, "  recorder replay <events.jsonl> <out.jsonl>  chain a stream of events")
	fmt.Fprintln(os.Stderr, "  recorder watch  <dir> <out.jsonl>         record file ops in a directory")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		os.Exit(cmdVerify(os.Args[2]))
	case "replay":
		if len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		os.Exit(cmdReplay(os.Args[2], os.Args[3]))
	case "watch":
		if len(os.Args) != 4 {
			usage()
			os.Exit(2)
		}
		os.Exit(cmdWatch(os.Args[2], os.Args[3]))
	default:
		usage()
		os.Exit(2)
	}
}

func cmdVerify(path string) int {
	l, err := Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load error:", err)
		return 2
	}
	ok, problems := l.Verify()
	if ok {
		fmt.Printf("OK: %d records, chain intact\n", len(l.records))
		return 0
	}
	fmt.Println("TAMPERED:")
	for _, p := range problems {
		fmt.Println("  -", p)
	}
	return 1
}

// cmdReplay reads a JSONL stream of {"recorded_at": <int ns>, "event": {...}}
// lines, chains them, and writes a full ledger. Event values must be strings
// (integer/string only is the cross-language contract).
func cmdReplay(in, out string) int {
	f, err := os.Open(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer f.Close()
	l := &Ledger{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev struct {
			RecordedAt int64          `json:"recorded_at"`
			Event      map[string]any `json:"event"`
		}
		if err := json.Unmarshal(line, &ev); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if _, err := l.Append(ev.RecordedAt, ev.Event); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := l.Dump(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("recorded %d events -> %s\n", len(l.records), out)
	return 0
}

// cmdWatch polls a directory and records create/write ops to the ledger. Poll
// keeps the demo dependency-free; production would swap the loop for fsnotify.
func cmdWatch(dir, out string) int {
	l := &Ledger{}
	if existing, err := Load(out); err == nil {
		l = existing
	}
	seen := map[string]int64{}
	fmt.Printf("watching %s (poll); ledger -> %s; Ctrl-C to stop\n", dir, out)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			mt := info.ModTime().UnixNano()
			prev, ok := seen[e.Name()]
			op := ""
			switch {
			case !ok:
				op = "create"
			case mt != prev:
				op = "write"
			}
			if op != "" {
				if _, err := l.Append(time.Now().UnixNano(),
					map[string]any{"file_id": e.Name(), "op": op}); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return 2
				}
				seen[e.Name()] = mt
				if err := l.Dump(out); err != nil {
					fmt.Fprintln(os.Stderr, err)
					return 2
				}
				fmt.Printf("  %s %s\n", op, e.Name())
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}
