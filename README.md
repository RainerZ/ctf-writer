# ctf-writer

Tiny pure-Rust library for writing a minimal CTF 1.8 trace directory.

This is intended to be used from a logger project that already knows about task
switches and timestamps. It intentionally avoids Babeltrace, `babeltrace2-sys`,
C build tools, and third-party Rust crates.

It writes:

```text
trace-dir/
├── metadata
└── stream
```

The only event type currently emitted is an LTTng-shaped `sched_switch`. Trace
Compass successfully imported and decoded this event shape after we added CTF
alignment padding.

## Use As A Path Dependency

From another local Rust project:

```toml
[dependencies]
ctf-writer = { path = "../ctf-writer" }
```

Rust imports package names with hyphens as underscores:

```rust
use ctf_writer::{CtfWriter, Task};

let mut ctf = CtfWriter::create("trace-out")?;
ctf.sched_switch(
    25_000,
    Task { name: "sensor", tid: 2, prio: 3 },
    Task { name: "control", tid: 3, prio: 4 },
)?;
ctf.finish()?;
# Ok::<(), std::io::Error>(())
```

Timestamps are nanoseconds on a monotonic 1 GHz CTF clock.

## Demo

```bash
cargo run
```

This creates:

```text
demo-trace-aligned/
├── metadata
└── stream
```

Import `demo-trace-aligned/` in Trace Compass as a CTF trace. The Events view
should show rows like:

```text
sched_switch prev_comm="IDLE", prev_tid=1, next_comm="sensor", next_tid=2
```

If Babeltrace 2 is installed, you can also inspect it with:

```bash
babeltrace2 demo-trace-aligned
```

## Important Implementation Context

CTF binary fields are alignment-sensitive. This project tracks the byte position
in the stream and inserts padding before 64-bit fields. Without this, Trace
Compass accepts the trace but decodes garbage values.

Current binary event layout:

```text
event header:
  uint32 id
  padding to 8-byte boundary
  uint64 timestamp_ns

sched_switch payload:
  nul-terminated prev_comm string
  padding to 8-byte boundary
  int64 prev_tid
  int64 prev_prio
  int64 prev_state
  nul-terminated next_comm string
  padding to 8-byte boundary
  int64 next_tid
  int64 next_prio
```

Current metadata intentionally omits an explicit stream id. Earlier, Trace
Compass reported that the stream had an id but no stream id in the packet
header. For this one-stream demo, omitting the stream id made the trace import.

## Limitations

This is not a general CTF writer. It is a deliberately small starting point:

- one stream file
- one event type: `sched_switch`
- little-endian integers
- no packet context
- no buffering/packet size metadata
- no CPU id field yet
- no `sched_wakeup` or IRQ events yet
- no validation beyond Rust I/O errors

Good next steps for a FreeRTOS logger are:

- add an API that remembers the previous task, such as `switch_to(timestamp, task)`
- add `sched_wakeup` if Trace Compass Control Flow needs wakeup edges
- add a configurable clock frequency if timestamps are not already nanoseconds
- decide whether task ids should be stable synthetic ids or original RTOS handles
