
use nom::*;
use nom::IResult::*;
use low::{Id, ProcessId, RspError};
use util::decode_hex;
use std::io;

/// Accept two hex digits and convert them to a `u8`.
pub fn parse_2_hex(input: &[u8]) -> IResult<&[u8], u8> {
    match take!(input, 2) {
        Done(rest, hex) => {
            match decode_hex(hex) {
                None => {
                    let pos = Err::Position(ErrorKind::HexDigit, input);
                    return Error(pos);
                },
                Some(v) => IResult::Done(rest, v as u8)
            }
        },
        Incomplete(x) => Incomplete(x),
        Error(x) => Error(x),
    }
}

/// Parse a big-endian hex sequence as a number.
named!(pub parse_hex_number<&[u8], u64>,
       fold_many1!(parse_2_hex, 0u64,
                   |acc, item| { acc * 256 + item as u64 }));

/// Parse an RSP error response.
named!(pub parse_error<&[u8], u8>,
       chain!(tag!("E")
              ~ result: parse_2_hex
              ~ eof
              , || result));

/// Parse an RSP "OK" response.
named!(pub parse_ok<&[u8], ()>,
       chain!(tag!("OK")
              ~ eof
              , || ()));

#[derive(Debug)]
pub enum ClientError {
    /// A wrapped RspError
    RspError(RspError),
    /// An error packet.  (FIXME distinguish from an error)
    ErrorPacket(u8),
    /// Unsupported request.
    Unsupported,
    /// Unrecognized response.
    Unrecognized,
}

pub type ClientResult<T> = Result<T, ClientError>;

impl From<RspError> for ClientError {
    fn from(t: RspError) -> Self {
        ClientError::RspError(t)
    }
}

impl From<io::Error> for ClientError {
    fn from(t: io::Error) -> Self {
        ClientError::RspError(RspError::IOError(t))
    }
}

/// Parse a simple RSP reply.  A simple reply is defined here as
/// either the empty packet (meaning that the request packet is not
/// recognized); an OK packet; or an error packet.
named!(pub parse_simple_reply<&[u8], ClientResult<()> >,
       alt_complete!(parse_ok => { |_| Ok(()) }
                     | parse_error => { |e| Err(ClientError::ErrorPacket(e)) }
                     | eof => { |_| Err(ClientError::Unsupported) }));

/// Parse a sequence of paired hex digits into a vector.
named!(pub parse_hex_data<&[u8], Vec<u8> >,
       many1!(parse_2_hex));

/// Parse a stop-reply signal packet.
named!(pub parse_stop_signal<&[u8], u8>,
       chain!(tag!("S")
              ~ value: parse_2_hex
              ~ eof
              , || value));

pub enum StopReplyValue {
    Register(u64, Vec<u8>),
    Thread(ProcessId),
    Core(u64),
    Unknown(Vec<u8>),
    Watch(u64),
    Awatch(u64),
    Rwatch(u64),
    SyscallEntry(u64),
    SyscallReturn(u64),
    LibraryChange,
    ReplayLog(bool),
    SoftwareBreak,
    HardwareBreak,
    Fork(ProcessId),
    VFork(ProcessId),
    VForkDone,
    Exec(Vec<u8>),
    Create,
}

// Helper for T packet.  Parse a register number.
named!(parse_t_register<&[u8], StopReplyValue>,
       chain!(regno: parse_hex_number
              ~ tag!(":")
              ~ value: parse_hex_data
              , || StopReplyValue::Register(regno, value)));

// Helper for T packet.  Parse "thread".
named!(parse_t_thread<&[u8], StopReplyValue>,
       chain!(tag!("thread:")
              ~ id: parse_thread_id
              , || StopReplyValue::Thread(id)));

// Helper for T packet.  Parse "core".
named!(parse_t_core<&[u8], StopReplyValue>,
       chain!(tag!("core:")
              ~ core: parse_hex_number
              , || StopReplyValue::Core(core)));

// Helper for T packet.  Parse "watch".
named!(parse_t_watch<&[u8], StopReplyValue>,
       chain!(tag!("watch:")
              ~ addr: parse_hex_number
              , || StopReplyValue::Watch(addr)));

// Helper for T packet.  Parse "awatch".
named!(parse_t_awatch<&[u8], StopReplyValue>,
       chain!(tag!("awatch:")
              ~ addr: parse_hex_number
              , || StopReplyValue::Awatch(addr)));

// Helper for T packet.  Parse "rwatch".
named!(parse_t_rwatch<&[u8], StopReplyValue>,
       chain!(tag!("rwatch:")
              ~ addr: parse_hex_number
              , || StopReplyValue::Rwatch(addr)));

// Helper for T packet.  Parse "syscall_entry".
named!(parse_t_syscall_entry<&[u8], StopReplyValue>,
       chain!(tag!("syscall_entry:")
              ~ call: parse_hex_number
              , || StopReplyValue::SyscallEntry(call)));

// Helper for T packet.  Parse "syscall_return".
named!(parse_t_syscall_return<&[u8], StopReplyValue>,
       chain!(tag!("syscall_return:")
              ~ call: parse_hex_number
              , || StopReplyValue::SyscallReturn(call)));

// Read until ";" or eof.
named!(skip_until_semi<&[u8]>,
       alt_complete!(take_until!(";") | eof));

// Helper for T packet.  Parse "library".
named!(parse_t_library<&[u8], StopReplyValue>,
       chain!(tag!("library:")
              ~ skip_until_semi
              , || StopReplyValue::LibraryChange));

// Helper for T packet.  Parse "replaylog".
named!(parse_t_replaylog<&[u8], StopReplyValue>,
       chain!(tag!("replaylog:")
              ~ result: alt_complete!(tag!("begin") => { |_| true }
                                      | tag!("end") => { |_| false })
              , || StopReplyValue::ReplayLog(result)));

// Helper for T packet.  Parse "swbreak".
named!(parse_t_swbreak<&[u8], StopReplyValue>,
       value!(StopReplyValue::SoftwareBreak, tag!("swbreak:")));

// Helper for T packet.  Parse "hwbreak".
named!(parse_t_hwbreak<&[u8], StopReplyValue>,
       value!(StopReplyValue::HardwareBreak, tag!("hwbreak:")));

// Helper for T packet.  Parse "fork".
named!(parse_t_fork<&[u8], StopReplyValue>,
       chain!(tag!("fork:")
              ~ pid: parse_thread_id
              , || StopReplyValue::Fork(pid)));

// Helper for T packet.  Parse "vfork".
named!(parse_t_vfork<&[u8], StopReplyValue>,
       chain!(tag!("vfork:")
              ~ pid: parse_thread_id
              , || StopReplyValue::VFork(pid)));

// Helper for T packet.  Parse "vforkdone".
named!(parse_t_vforkdone<&[u8], StopReplyValue>,
       chain!(tag!("vforkdone:")
              ~ skip_until_semi
              , || StopReplyValue::VForkDone));

// Helper for T packet.  Parse "exec".
named!(parse_t_exec<&[u8], StopReplyValue>,
       chain!(tag!("exec:")
              ~ path: parse_hex_data
              , || StopReplyValue::Exec(path)));

// Helper for T packet.  Parse "create".
named!(parse_t_create<&[u8], StopReplyValue>,
       chain!(tag!("create:")
              ~ skip_until_semi
              , || StopReplyValue::Create));

// Helper for T packet.  Parse any single `T` pair.
named!(parse_any_t_pair<&[u8], StopReplyValue>,
       alt_complete!(parse_t_register
                     | parse_t_thread
                     | parse_t_core
                     | parse_t_watch
                     | parse_t_awatch
                     | parse_t_rwatch
                     | parse_t_syscall_entry
                     | parse_t_syscall_return
                     | parse_t_library
                     | parse_t_replaylog
                     | parse_t_swbreak
                     | parse_t_hwbreak
                     | parse_t_fork
                     | parse_t_vfork
                     | parse_t_vforkdone
                     | parse_t_exec
                     | parse_t_create));

/// Parse a stop-reply long-form signal (`T`) packet.
named!(pub parse_stop_signal_full<&[u8], (u8, Vec<StopReplyValue>) >,
       chain!(tag!("T")
              ~ signo: parse_2_hex
              ~ values: separated_nonempty_list!(tag!(";"), parse_any_t_pair)
              ~ eof
              , || (signo, values)));

/// Parse a stop-reply exit packet.
named!(pub parse_stop_exit<&[u8], (u8, Option<u64>)>,
       chain!(tag!("W")
              ~ value: parse_2_hex
              ~ pid: opt!(
                  chain!(tag!(";process:")
                         ~ pid: parse_hex_number
                         , || pid))
              ~ eof
              , || (value, pid)));

/// Parse a stop-reply exited-with-signal packet.
named!(pub parse_stop_exit_signal<&[u8], (u64, Option<u64>)>,
       chain!(tag!("X")
              // The docs say this takes two digits but in reality any
              // number of digits is accepted.
              ~ value: parse_hex_number
              ~ pid: opt!(
                  chain!(tag!(";process:")
                         ~ pid: parse_hex_number
                         , || pid))
              ~ eof
              , || (value, pid)));

/// Parse a stop-reply thread-exited packet.
named!(pub parse_stop_thread_exit<&[u8], (u64, u64)>,
       chain!(tag!("w")
              // The docs say this takes two digits but in reality any
              // number of digits is accepted.
              ~ value: parse_hex_number
              ~ tag!(";")
              ~ pid: parse_hex_number
              ~ eof
              , || (value, pid)));

/// Parse an inferior output packet.
named!(pub parse_inferior_output<&[u8], Vec<u8> >,
       chain!(tag!("O")
              ~ data: parse_hex_data
              , { || data }));

/// Helper for parse_thread_id that parses a single thread-id element.
named!(pub parse_thread_id_element<&[u8], Id>,
       alt_complete!(tag!("0") => { |_| Id::Any }
                     | tag!("-1") => { |_| Id::All }
                     | parse_hex_number => { |val: u64| Id::Id(val as u32) }));

/// Parse a thread-id.
named!(pub parse_thread_id<&[u8], ProcessId>,
       alt_complete!(parse_thread_id_element => { |pid| ProcessId { pid: pid, tid: Id::Any } }
                     | chain!(tag!("p")
                              ~ pid: parse_thread_id_element
                              ~ tag!(".")
                              ~ tid: parse_thread_id_element
                              // FIXME error checking here?
                              , { || ProcessId { pid: pid, tid: tid } })));

/// Parse the result of the `qC` packet.  Note that this does not
/// handle the "anything else" case; that must be done elsewhere.
named!(pub parse_qc_reply<&[u8], ProcessId>,
       chain!(tag!("QC")
              ~ id: parse_thread_id
              , { || id }));

/// Parse a comma-separated list of thread ids.
named!(pub parse_thread_id_list<&[u8], Vec<ProcessId> >,
       chain!(first: parse_thread_id
              ~ mut rest: many0!(chain!(tag!(",")
                                        ~ id: parse_thread_id
                                        , || { id }))
              , || {
                  rest.insert(0, first);
                  rest
              }));

/// Parse a single `qfThreadInfo` or `qsThreadInfo` reply.
named!(pub parse_thread_info_reply<&[u8], Option<Vec<ProcessId>> >,
       alt_complete!(tag!("l") => { |_| None }
                     | parse_thread_id_list => { |v| Some(v) }));

/// Parse a `qSymbol` response.
named!(pub parse_qsymbol<&[u8], Option<Vec<u8>> >,
       alt_complete!(tag!("OK") => { |_| None }
                     | chain!(tag!("qSymbol:")
                              ~ data: parse_hex_data
                              , || { data }) => { |v| Some(v) }));

/// Parse a memory packet (`m`) response.
named!(pub parse_memory<&[u8], ClientResult< Vec<u8> > >,
       alt_complete!(parse_error => { |e| Err(ClientError::ErrorPacket(e)) }
                     | parse_hex_data => { |data| Ok(data) }
                     | eof => { |_| Err(ClientError::Unsupported) }));

