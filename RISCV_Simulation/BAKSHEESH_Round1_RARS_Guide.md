# Running BAKSHEESH Round 1 in RARS — Step-by-Step Guide

This walks you through, from zero, how to get a RISC-V simulator, load the
`baksheesh_round1.s` program, run it, and actually *see* the round happening
register-by-register.

## 1. Install Java (if you don't have it)

RARS is a Java program (a single `.jar` file), so you need a Java Runtime.
Check first:

```
java -version
```

If that fails, install a JRE:
- **Windows/Mac**: download from https://adoptium.net (choose the latest LTS,
  e.g. Temurin 21) and run the installer.
- **Linux (Debian/Ubuntu)**: `sudo apt install default-jre`

## 2. Get RARS

**I've already included `rars.jar` in this delivery** — you can skip straight
to step 3. If you ever want to fetch it yourself (e.g. a newer version, or on
a different machine), the official source is:

- Official repo: https://github.com/TheThirdOne/rars
- Direct download of the exact version I tested this with: https://github.com/TheThirdOne/rars/releases/download/v1.6/rars1_6.jar

RARS is not "installed" in the traditional sense — it's a single jar file you
just keep somewhere and run with `java -jar rars.jar`.

## 3. Open the program in RARS (GUI mode)

```
java -jar rars.jar
```

This opens the RARS window. Then:

1. **File → Open...** and select `baksheesh_round1.s`.
2. Click **Assemble** (or press **F3**). The bottom pane should say
   "Assemble operation completed successfully" with no errors. If you see
   errors, they'll point to a line number in the editor — nothing should be
   wrong if you're using the file as delivered.
3. Switch to the **Execute** tab (RARS does this automatically after a
   successful assemble).

## 4. Visualize the simulation

This is the part you asked about — here's how to actually *watch* Round 1
happen:

- **Registers window** (right-hand side, "Registers" tab): this shows all
  32 registers live. Keep an eye on:
  - `x10`–`x13` (labeled `a0`–`a3`) — these ARE the cipher state `S0..S3`.
  - `x18`–`x21` (`s2`–`s5`) — the master key words.
  - `x22`–`x25` (`s6`–`s9`) — the round-2 subkey words.
  - `x5`,`x6`,`x7` (`t0`–`t2`) and `x28`–`x31` (`t3`–`t6`) — loop counters and
    scratch values inside `sub_cells`/`perm_bits`/`add_constants_round1`;
    watching these tells you exactly which nibble/bit the program is
    currently processing.
- **Text Segment window** ("Text Segment" tab): shows the disassembled
  instructions with a highlighted arrow marking the next instruction to
  execute — this is your "program counter" view.
- **Run I/O window** (bottom): this is where the program's printed output
  (the hex dumps after each stage) appears.

To actually step through it:
- **Step (F7)**: executes exactly one instruction. Do this repeatedly and
  watch `x10`-`x13` change as each `xor`, `sbox` lookup, or bit-permute
  happens. This is the slowest but most instructive way to see Round 1.
- **Go (F5)**: runs to completion (or to a breakpoint) in one shot.
- **Breakpoints**: click in the leftmost column of the Text Segment view
  next to a line (e.g. the `call sub_cells` line, or `sc_done:`) to set a
  breakpoint, then press **Go** — execution stops right there so you can
  inspect registers before continuing.

A good first walkthrough: set a breakpoint at each of these labels and press
**Go** repeatedly, checking `x10`-`x13` at each stop:
1. `sc_done` — right after SubCells finishes (compare against "y" in the
   expected output below).
2. `pb_done` — right after PermBits finishes.
3. `ac_done` — right after AddConstants finishes (this + PermBits together
   correspond to "z" in the expected output).
4. The final `xor x13, x13, x25` line — right after AddRoundKey (this is the
   final Round 1 output).

## 5. Run it non-interactively (just see the output)

If you just want the printed result without the GUI:

```
java -jar rars.jar nc baksheesh_round1.s
```

(`nc` = "no copyright banner". Output goes straight to your terminal.)

## 6. What you should see

Using the built-in test vector (key `76543210032032032032032032032032`,
plaintext `789a789a789a789a789a789a789a789a` — vector #6 from BAKSHEESH's own
Table 14), the program prints four 128-bit values, each as four 32-bit hex
words **S3 S2 S1 S0** (most-significant word first):

```
[round 1] x  (after initial whitening, input to SubCells), S3..S0:
0ece4a8a 7bba4a99 58a87bba 4a9958a8
[round 1] y  (after SubCells),                              S3..S0:
3747b9c9 e229b9ff 5c9ce229 b9ff5c9c
[round 1] z  (after PermBits + AddConstants),               S3..S0:
28e9de9d 7b2fc2fc 7d0f90f9 59bb6bb4
[round 1] state (after AddRoundKey w/ k2) -- ROUND 1 OUTPUT, S3..S0:
13c3c795 7abfdbfd ed169169 40bafbad
```

I generated these expected values independently from the reference Python
implementation (`baksheesh_lfa/src/baksheesh.py`), so if your RARS run
matches this exactly, your Round 1 datapath is verified correct end to end
(AddRoundKey → SubCells → PermBits → AddConstants → AddRoundKey).

## 7. Two real bugs I hit writing this (worth knowing before you extend it)

Both are documented in comments at the top of `baksheesh_round1.s`, but
they're common enough RISC-V traps that they're worth calling out directly:

1. **`x10`-`x13` are also `a0`-`a3`.** Since the assignment asks for the
   state to live in `x10`-`x13`, *any* function call that uses the normal
   argument-passing convention (including the print/ecall routines) will
   clobber your cipher state unless you explicitly save and restore it
   around the call. `print_state` does this by copying S0-S3 to the stack
   the instant it's entered.
2. **The `call` pseudo-instruction uses `t1` (`x6`) as scratch.** It expands
   to `auipc t1, ...` + `jalr ra, ...(t1)` under the hood. If you're passing
   a value to a function in `t1` and then execute `call`, that value is
   destroyed before the callee runs. Either avoid `t1` for values that need
   to survive a `call`, or (as this file now does) use plain `jal ra, label`
   instead of `call`.

## 8. Extending this to full 35-round BAKSHEESH (optional next step)

`sub_cells`, `perm_bits`, and the general structure of `add_constants_round1`
are already written as reusable subroutines. To go from Round 1 to the full
cipher you'd mainly need to:
- Turn the key schedule into a loop that computes `k[r+1] = ror128(k[r], 1)`
  each round (a 128-bit rotate-right-by-1 across the four words, using
  `srl`/`sll`/`or` with carry between words — same idea as the bit
  permutation loop, just simpler).
- Generalize `add_constants_round1` into `add_constants` that reads the
  6-bit constant for round `r` from a 35-entry table (the `ROUND_CONSTANTS_6BIT`
  table already in `constants.py`) instead of hardcoding `2`.
- Wrap the whole round body (SubCells → PermBits → AddConstants →
  AddRoundKey) in an outer loop from `r=1` to `r=35`.

Happy to build that out next if you want the full cipher rather than just
Round 1.
