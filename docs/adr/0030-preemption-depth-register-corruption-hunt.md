# ADR-0030: The preemption-depth register-corruption hunt (round X) — status: OPEN, reproduction on demand

## Context

The ~1-in-5 boot flake recorded in the slice-4 changelog ("a lane flake in
the slice-3/preempt interplay") was picked up as the next round's target.
Two distinct failure shapes had been observed once each at the default
10 ms tick: the CoW demo failing with `parent_ok=0 child_ok=0 copies=1`
(the parent's store never faulting — it never ran — and the child's
read-back mismatching), and round W's mode-13 wait4 failure (a child's
completion entry surfacing unconsumed in kmain's drain).

## The reproduction (the round's first win)

**Shrinking the tick interval 8× (10 ms → 1.25 ms,
`set_tick_interval(hz/800)` + the `TICK_INTERVAL_TSC` fallback) makes the
failure fire on EVERY boot** — 3/3 boots failed with the signal demo's
verdict (`[M3] signal: ERROR: victim/killer exit wrong`), always with
`completed dom=23 code=fault`. The trigger is the tick density alone:
boots with the switch-path debug prints removed still failed 3/3, and
boots at 10 ms with the prints stayed green 18 consecutive times. The
original flake is this bug in the narrow window; dense ticks widen the
window to certainty.

(A false trail worth recording: "boots under host CPU contention"
produced what looked like hangs — those were QEMU slowness, the rogue
demo needing 150k strikes finishing ~50k in 300 s, NOT the bug. The
rogue strike count told the truth: green boots print exactly 150,000
domain-12 audits.)

## The evidence (the dying register file)

The victim (dom 23, the signal demo) dies at `mov %al,(%rdi)` —
`rdi=0xA`, i.e. **the SIGUSR1 argument value** — inside the hex-print
helper the victim's handler calls. The full register file at death:

```
r15=0x102000   r14=0x23        r13=0x202       r12=0x2b
r11=0x246      r10=0x400000    r9=0x2          r8=0
rbp=0x409000   rdi=0xA         rsi=0x4030400   rdx=0xD
rcx=0x400b1b   rbx=0x400000    rax=0x30 ('0')
rip=0x400b17   rsp=0x408f70
```

Decode: `rax=0x30` and `rcx=0x400b1b` mean the helper was mid-format
(the victim was alive and running INSIDE its handler); `rdi=0xA` means
the helper was entered with the handler-ENTRY rdi (the signal number)
instead of the output buffer. And the callee-saved set carries
**user-context-STRUCT fields, not user values**: `r12=0x2b` is the user
CS, `r13=0x202` is USER_RFLAGS, `r14=0x23` is the domain id, `r15=0x102000`
is a physical address, `rbp=0x409000` is STACK_TOP. The handler was
entered with a register file that is not any legitimate interrupted-user
state — its registers hold fields of a context structure.

## The diagnosis (narrowed, not yet pinned)

A user run is resumed with a corrupted register file — values that
belong to context STRUCTS (cs/rflags/domain/pa) landing in the
callee-saved slots — and dies on first use (the handler's helper writes
through rdi=0xA). The corrupting event happens somewhere in the
park/resume pipeline, and the pipeline has four register-capture sites:

1. `park_from_frame` (the tick) — reads the IRQ frame via `gpr_at`,
   symmetric with `unpark_into_frame`'s `set_gpr_at`; the
   spinner/writer demo survives 9+ switches/boot, so this pair is
   probably sound.
2. `parked_from_current_syscall` (yield/nanosleep/IPC/wait arms) —
   reads the stub frame slots (`frame_word(OFF_*)`) and the stub's
   callee-saved slots (`user_callee_saved()`).
3. `deliver_to_parked` (the signal path) — builds `InterruptedImage`
   from the ctx gprs and rewrites rip/rsp/rdi/rax only; verified
   correct by reading.
4. `sys_sigreturn` — validated the cookie/address, refused NOTHING in
   the failing boots (probe-verified: no refusal prints fired).

This is the **third member of the ADR-0010 family** (the mirror-inverted
stub offsets; the yield path's garbage r12 "found live"; the
rip-read-from-RSI-slot "found live"). Every prior member was a
slot/offset misalignment between an asm stub and its Rust reader. The
prime suspects are the per-excursion shared slots: `user_callee_saved()`
and the `PARK_RBX..PARK_R15` resume slots — at a NESTED park depth
(a dispatcher-resumed run parking again under tick pressure) some reader
picks up slots written by a different excursion than the one it belongs
to. Dense ticks multiply the nesting frequency; that is exactly why the
window opens.

Two sibling observations that now belong to this hunt:
- Round X's first captured CoW failure (`copies=1`, parent stranded)
  fits the same class: a parked image corrupted → the child's
  post-CoW read-back mismatched (its r12-class registers corrupted
  on resume), and the parent never resumed (its parked image or its
  runnable bit lost).
- Round W's mode-13 wait4 failure (a completion unconsumed) is
  plausibly the same corruption killing a waiter/park transition in a
  rare interleaving.

## The next moves (the next round's opening)

1. Read `arch/syscall_entry.rs`'s `user_callee_saved()` and the
   `PARK_*` slot writers/readers; map WHICH slots the dying values
   {0x2b, 0x202, 0x23, 0x102000} physically come from — the struct
   whose fields they are is the struct a reader is mis-indexing.
2. Add a debug probe at every `parked_from_current_syscall` capture:
   print the captured `live` five; if {0x2b/0x202/0x23-class} values
   appear at capture time (not just at death), the capture is the
   corrupter; if they appear only later, the stash/restore is.
3. Keep the 8× density as the reproduction knob until fixed; the fix
   must turn 3/3 failures into 3/3 greens at 1.25 ms, then hold across
   ≥10 boots at 10 ms.

## Status

OPEN. No production code changed in round X — all instrumentation
(tick density, blob amplifier loop, probe prints, the dying-register
dump) was reverted; the evidence logs are archived in the session
bundle. The hunt dossier is this document.
