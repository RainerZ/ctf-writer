use ctf_writer::{CtfWriter, Task};
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let output_dir = PathBuf::from("demo-trace-aligned");
    let idle = Task {
        name: "IDLE",
        tid: 1,
        prio: 0,
    };
    let sensor = Task {
        name: "sensor",
        tid: 2,
        prio: 3,
    };
    let control = Task {
        name: "control",
        tid: 3,
        prio: 4,
    };

    let mut ctf = CtfWriter::create(&output_dir)?;
    ctf.sched_switch(0, idle.clone(), sensor.clone())?;
    ctf.sched_switch(25_000, sensor.clone(), control.clone())?;
    ctf.sched_switch(75_000, control.clone(), sensor.clone())?;
    ctf.sched_switch(100_000, sensor, idle)?;
    ctf.finish()?;

    println!("Wrote {}", output_dir.display());
    println!("Try: babeltrace2 {}", output_dir.display());
    Ok(())
}
