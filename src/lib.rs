use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;

const SCHED_SWITCH_ID: u32 = 0;

#[derive(Debug)]
pub struct CtfWriter {
    stream: BufWriter<File>,
    pos: u64,
}

#[derive(Debug, Clone)]
pub struct Task<'a> {
    pub name: &'a str,
    pub tid: i64,
    pub prio: i64,
}

impl CtfWriter {
    pub fn create(output_dir: impl AsRef<Path>) -> io::Result<Self> {
        let output_dir = output_dir.as_ref();
        fs::create_dir_all(output_dir)?;
        fs::write(output_dir.join("metadata"), metadata())?;

        let stream = BufWriter::new(File::create(output_dir.join("stream"))?);
        Ok(Self { stream, pos: 0 })
    }

    pub fn sched_switch(
        &mut self,
        timestamp_ns: u64,
        prev: Task<'_>,
        next: Task<'_>,
    ) -> io::Result<()> {
        self.write_event_header(SCHED_SWITCH_ID, timestamp_ns)?;
        self.write_cstr(prev.name)?;
        self.align_to(8)?;
        self.write_i64(prev.tid)?;
        self.write_i64(prev.prio)?;
        self.write_i64(0)?; // prev_state: TASK_RUNNING
        self.write_cstr(next.name)?;
        self.align_to(8)?;
        self.write_i64(next.tid)?;
        self.write_i64(next.prio)?;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.stream.flush()
    }

    fn write_event_header(&mut self, id: u32, timestamp_ns: u64) -> io::Result<()> {
        self.write_u32(id)?;
        self.align_to(8)?;
        self.write_u64(timestamp_ns)
    }

    fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.stream.write_all(&value.to_le_bytes())?;
        self.pos += 4;
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> io::Result<()> {
        self.stream.write_all(&value.to_le_bytes())?;
        self.pos += 8;
        Ok(())
    }

    fn write_i64(&mut self, value: i64) -> io::Result<()> {
        self.align_to(8)?;
        self.stream.write_all(&value.to_le_bytes())?;
        self.pos += 8;
        Ok(())
    }

    fn write_cstr(&mut self, value: &str) -> io::Result<()> {
        self.stream.write_all(value.as_bytes())?;
        self.stream.write_all(&[0])?;
        self.pos += value.len() as u64 + 1;
        Ok(())
    }

    fn align_to(&mut self, align: u64) -> io::Result<()> {
        let padding = (align - (self.pos % align)) % align;
        for _ in 0..padding {
            self.stream.write_all(&[0])?;
        }
        self.pos += padding;
        Ok(())
    }
}

fn metadata() -> &'static str {
    r#"/* CTF 1.8 metadata: intentionally tiny demo trace. */
typealias integer { size = 8; align = 8; signed = false; } := uint8_t;
typealias integer { size = 32; align = 32; signed = false; } := uint32_t;
typealias integer { size = 64; align = 64; signed = true; } := int64_t;
typealias integer { size = 64; align = 64; signed = false; } := uint64_t;

trace {
    major = 1;
    minor = 8;
    byte_order = le;
};

env {
    hostname = "ctf-writer";
    domain = "kernel";
    tracer_name = "lttng-modules";
    tracer_major = 2;
    tracer_minor = 12;
    tracer_patchlevel = 5;
    trace_buffering_scheme = "global";
};

clock {
    name = monotonic;
    freq = 1000000000;
    offset_s = 0;
    offset = 0;
};

typealias integer {
    size = 64;
    align = 64;
    signed = false;
    map = clock.monotonic.value;
} := uint64_clock_monotonic_t;

stream {
    event.header := struct {
        uint32_t id;
        uint64_clock_monotonic_t timestamp;
    };
};

event {
    name = sched_switch;
    id = 0;
    fields := struct {
        string prev_comm;
        int64_t prev_tid;
        int64_t prev_prio;
        int64_t prev_state;
        string next_comm;
        int64_t next_tid;
        int64_t next_prio;
    };
};
"#
}
