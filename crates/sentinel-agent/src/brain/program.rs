use byteflow::Program;

#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    On = 0,
    Off = 1,
    Status = 2,
}

impl OpCode {
    pub fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::On,
            1 => Self::Off,
            2 => Self::Status,
            _ => Self::Status,
        }
    }
}

pub fn brain_program() -> byteflow::Chunk {
    const NATIVE_SENTINEL_RUN: u32 = 8;
    let mut program = Program::new("sentinel-brain");
    program.function("main", 1, |f| {
        let op = f.reg(0);
        f.call_native(op, NATIVE_SENTINEL_RUN, 1);
        f.return_(op);
    });
    program.build()
}
