use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

const SCHED_SWITCH_ID: u32 = 0;
const TEXT_LOG_ID: u32 = 1;
const STREAM_ID: u32 = 0;
const CPU_ID: u32 = 0;
const CTF_MAGIC: u32 = 0xC1FC_1FC1;
const PACKET_PREAMBLE_SIZE: u64 = 48;

#[derive(Debug)]
pub struct CtfWriter {
    output_dir: PathBuf,
    events: Vec<u8>,
    pos: u64,
    timestamp_begin_ns: Option<u64>,
    timestamp_end_ns: u64,
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

        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            events: Vec::new(),
            pos: PACKET_PREAMBLE_SIZE,
            timestamp_begin_ns: None,
            timestamp_end_ns: 0,
        })
    }

    pub fn sched_switch(
        &mut self,
        timestamp_ns: u64,
        prev: Task<'_>,
        next: Task<'_>,
    ) -> io::Result<()> {
        self.observe_timestamp(timestamp_ns);
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

    pub fn text_log(&mut self, timestamp_ns: u64, message: &str) -> io::Result<()> {
        self.observe_timestamp(timestamp_ns);
        self.write_event_header(TEXT_LOG_ID, timestamp_ns)?;
        self.write_cstr(message)
    }

    pub fn finish(self) -> io::Result<()> {
        let packet_size_bits = (PACKET_PREAMBLE_SIZE + self.events.len() as u64) * 8;
        let timestamp_begin_ns = self.timestamp_begin_ns.unwrap_or(0);

        let stream = File::create(self.output_dir.join("stream"))?;
        let mut stream = BufWriter::new(stream);

        stream.write_all(&CTF_MAGIC.to_le_bytes())?;
        stream.write_all(&STREAM_ID.to_le_bytes())?;

        stream.write_all(&CPU_ID.to_le_bytes())?;
        stream.write_all(&0_u32.to_le_bytes())?; // padding before 64-bit fields
        stream.write_all(&timestamp_begin_ns.to_le_bytes())?;
        stream.write_all(&self.timestamp_end_ns.to_le_bytes())?;
        stream.write_all(&packet_size_bits.to_le_bytes())?;
        stream.write_all(&packet_size_bits.to_le_bytes())?;

        stream.write_all(&self.events)?;
        stream.flush()
    }

    fn observe_timestamp(&mut self, timestamp_ns: u64) {
        if self.timestamp_begin_ns.is_none() {
            self.timestamp_begin_ns = Some(timestamp_ns);
        }
        self.timestamp_end_ns = timestamp_ns;
    }

    fn write_event_header(&mut self, id: u32, timestamp_ns: u64) -> io::Result<()> {
        self.align_to(8)?;
        self.write_u32(id)?;
        self.align_to(8)?;
        self.write_u64(timestamp_ns)
    }

    fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.events.write_all(&value.to_le_bytes())?;
        self.pos += 4;
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> io::Result<()> {
        self.events.write_all(&value.to_le_bytes())?;
        self.pos += 8;
        Ok(())
    }

    fn write_i64(&mut self, value: i64) -> io::Result<()> {
        self.align_to(8)?;
        self.events.write_all(&value.to_le_bytes())?;
        self.pos += 8;
        Ok(())
    }

    fn write_cstr(&mut self, value: &str) -> io::Result<()> {
        self.events.write_all(value.as_bytes())?;
        self.events.write_all(&[0])?;
        self.pos += value.len() as u64 + 1;
        Ok(())
    }

    fn align_to(&mut self, align: u64) -> io::Result<()> {
        let padding = (align - (self.pos % align)) % align;
        for _ in 0..padding {
            self.events.write_all(&[0])?;
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
    packet.header := struct {
        uint32_t magic;
        uint32_t stream_id;
    };
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
    id = 0;
    packet.context := struct {
        uint32_t cpu_id;
        uint64_clock_monotonic_t timestamp_begin;
        uint64_clock_monotonic_t timestamp_end;
        uint64_t content_size;
        uint64_t packet_size;
    };

    event.header := struct {
        uint32_t id;
        uint64_clock_monotonic_t timestamp;
    };
};

event {
    name = sched_switch;
    id = 0;
    stream_id = 0;
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

event {
    name = text_log;
    id = 1;
    stream_id = 0;
    fields := struct {
        string message;
    };
};
"#
}
