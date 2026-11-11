---
name: fi-binary-analysis
description: Inspect compiled binaries with fi — symbol search and sizing, disassembly, DWARF source interleaving, inline-frame byte attribution, callsite lookup, data-section search — to verify codegen (for example whether SIMD instructions were emitted), compare code size between builds, and triage performance, crashes, or size regressions. Use when reading machine code from a linked executable, mapping addresses back to source lines, ranking the largest symbols, or checking inlined code — even when fi is not named.
---

# Binary analysis with fi

`fi` is a client/server binary inspector. One `fi listen` process holds a memory-mapped
binary; `fi search` and `fi show` query it over a Unix socket. Use it on **linked**
executables: with `lto = "fat"`, Rust archives hold LLVM IR bitcode, and static libraries
or `.o` files cannot be disassembled.

Build once if `fi` is missing (needs a C compiler for capstone):

```bash
git clone https://github.com/quininer/fi && cd fi && cargo build --release   # target/release/fi
```

## Session

`fi listen` blocks and prints the socket path on its first line, so start it in the
background and export `FI_SESSION` from that line:

```bash
FI=/path/to/fi/target/release/fi
FI_SESSION=/tmp/fi-myapp.sock $FI listen ./target/release/mybin > /tmp/fi-listen.log 2>&1 &
head -1 /tmp/fi-listen.log          # set -x FI_SESSION /tmp/fi-myapp.sock
export FI_SESSION=/tmp/fi-myapp.sock
$FI search -d -s 'regex'
$FI show 0x0000000000412a30 -d --dwarf
kill %1                             # the socket file is removed on SIGINT
```

Set `FI_SESSION` explicitly when more than one binary is loaded; without it, `fi` picks the
first socket whose path matches the current working directory, which is ambiguous.

A binary needs a symbol table for `fi search` and DWARF for `--dwarf`. Rust
`[profile.release]` with `strip = "symbols"` has neither, so build the artifact you inspect
with debug info — `[profile.bench]` (`opt-level = 3`, `lto = "fat"`, `debug = true`) keeps
codegen close to release while staying readable. `--dwarf` prints source text only when the
source files still exist at the paths recorded in DWARF.

## Commands

```
fi search <regex|address>      list matching symbols
  -d, --demangle               demangle names (use it; Rust names are otherwise mangled)
  -s, --size                   print symbol size, plus a total
      --sort-size | --sort_name    order results
      --only-duplicate         show names that occur more than once (inlining copies)
  -F, --filter-section <re>    restrict to sections
      --data                   search bytes of data sections instead of names
      --callsite <addr>        disassemble every text symbol and list those calling <addr>

fi show <address>              disassemble the symbol containing <address>
  -d, --demangle
      --dwarf                  interleave source lines from DWARF
      --dwarf --dwarf-top      byte count per function, sorted ascending
      --dump                   raw bytes
      --no-symbol -l <len> [--align n]   dump a section range without symbol lookup
```

## Gotchas (each one fails or misleads silently)

- **`--dwarf-top` needs `--dwarf`** as well, otherwise `exec failed: need --dward`.
- **`--dwarf-top` reports the second-innermost inline frame**, so an inlined helper is
  counted under its caller. For exact per-inlined-function code, read DWARF directly:

  ```bash
  llvm-dwarfdump --name='<mangled inlined function>' <binary>   # DW_TAG_inlined_subroutine
  ```

  `DW_AT_ranges` (or `DW_AT_low_pc`/`DW_AT_high_pc`) gives its address ranges;
  `DW_AT_call_line` gives the call site.
- `fi show <address>` always disassembles the **whole containing symbol** starting at its
  first byte; `-l/--length` is ignored for text symbols. Slice the output by address instead.
- On large binaries `--dwarf` and `--dwarf-top` are slow: redirect to a file and read the
  window you need, or run the command in the background.
- Output is written by the server through the passed file descriptors, so redirection works
  but `fi` prints nothing when the session points at the wrong socket.

## Recipes

Did the compiler emit SIMD for this loop?

```bash
$FI search -d -s 'hot_symbol'                     # address + size
$FI show <addr> -d --dwarf > /tmp/s.txt           # source-interleaved disassembly
grep -E '^0x' /tmp/s.txt | grep -cE '\b(movdqu|movdqa|movups|movaps|p[a-z]+b?|vp[a-z]+)\b'
```

Zero matches means no vector instructions. Compare the same symbol between two builds of the
same harness to confirm a codegen change, and check code size the same way (`-s` totals).

Which code belongs to an inlined helper:

```bash
llvm-dwarfdump --name="$($FI search <addr> | head -1 | awk '{print $NF}' | ...mangled...)" ...
```

Practical form: get the mangled name with `nm <binary> | grep <function>`, then sum the
`DW_AT_ranges` spans.

Who calls a function (slow on large binaries; needs a text symbol address):

```bash
$FI search --callsite 0x0000000000412a30 -d
```

Largest symbols in a section:

```bash
$FI search -d -s --sort-size '' -F '\.text' | tail -30
```

Cross-check hot code with `perf record -g` / `perf annotate` on the same binary; use `fi`
where DWARF inline info and source interleaving are needed, `perf` where dynamic samples are
needed.
