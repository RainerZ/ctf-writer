use ctf_writer::{CtfWriter, Task};
use std::io;
use std::path::PathBuf;

struct DemoRng {
    state: u64,
}

impl DemoRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (self.state >> 32) as u32
    }

    fn range(&mut self, min: u64, max: u64) -> u64 {
        min + u64::from(self.next_u32()) % (max - min + 1)
    }
}

fn main() -> io::Result<()> {
    let output_dir = PathBuf::from("demo-trace");
    let tasks = [
        Task {
            name: "IDLE",
            tid: 1,
            prio: 0,
        },
        Task {
            name: "sensor",
            tid: 2,
            prio: 3,
        },
        Task {
            name: "control",
            tid: 3,
            prio: 4,
        },
        Task {
            name: "logger",
            tid: 4,
            prio: 2,
        },
        Task {
            name: "comms",
            tid: 5,
            prio: 3,
        },
        Task {
            name: "ui",
            tid: 6,
            prio: 1,
        },
    ];

    let mut ctf = CtfWriter::create(&output_dir)?;
    let mut rng = DemoRng::new(0xC7F5_CAFE);
    let mut timestamp_ns = 0;
    let mut current = 0_usize;

    ctf.text_log(timestamp_ns, "demo trace started")?;

    for event_index in 0..250 {
        let duration_us = rng.range(20, 2_000);
        timestamp_ns += duration_us * 1_000;

        let mut next = if rng.next_u32() % 10 == 0 {
            0
        } else {
            1 + (rng.next_u32() as usize % (tasks.len() - 1))
        };

        if next == current {
            next = (next + 1) % tasks.len();
        }

        ctf.sched_switch(timestamp_ns, tasks[current].clone(), tasks[next].clone())?;

        if event_index % 40 == 0 {
            let message = format!(
                "scheduler sample {event_index}: {} -> {}",
                tasks[current].name, tasks[next].name
            );
            ctf.text_log(timestamp_ns + 1, &message)?;
        }

        if next == 0 && current != 0 {
            ctf.text_log(timestamp_ns + 2, "system is idle")?;
        }

        current = next;
    }

    ctf.text_log(timestamp_ns + 1_000, "demo trace finished")?;

    ctf.finish()?;

    println!("Wrote {}", output_dir.display());
    println!("Try: babeltrace2 {}", output_dir.display());
    Ok(())
}
