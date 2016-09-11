
use nom::*;
use nom::IResult::*;
use low::{Id, ProcessId};

/// Accept two hex digits and convert them to a `u8`.
pub fn parse_2_hex(input: &[u8]) -> IResult<&[u8], u8> {
    match take!(input, 2) {
        Done(rest, hex) => {
            let mut result = 0;
            for c in hex.iter() {
                match (*c as char).to_digit(16) {
                    None => {
                        let pos = Err::Position(ErrorKind::HexDigit, input);
                        return Error(pos);
                    },
                    Some(v) => result = result << 4 + v,
                }
            }
            IResult::Done(rest, result as u8)
        }
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

pub enum NormalPacketResponse {
    Ok,
    Unsupported,
    Error(u8),
    InvalidResponse,
}

/// Parse a simple RSP reply.  A simple reply is defined here as
/// either the empty packet (meaning that the request packet is not
/// recognized); an OK packet, or an error packet.
named!(pub parse_simple_reply<&[u8], NormalPacketResponse>,
       alt!(parse_ok => { |_| NormalPacketResponse::Ok }
            | parse_error => { |e| NormalPacketResponse::Error(e) }
            | eof => { |_| NormalPacketResponse::Unsupported }));

/// Parse a sequence of paired hex digits into a vector.
named!(pub parse_hex_data<&[u8], Vec<u8> >,
       many1!(parse_2_hex));

/// Parse a stop-reply signal packet.
named!(pub parse_stop_signal<&[u8], u8>,
       chain!(tag!("S")
              ~ value: parse_2_hex
              ~ eof
              , || value));

// FIXME 'T' packet

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
named!(pub parse_stop_exit_signal<&[u8], (u8, Option<u64>)>,
       chain!(tag!("X")
              ~ value: parse_2_hex // FIXME more is ok!!?
              ~ pid: opt!(
                  chain!(tag!(";process:")
                         ~ pid: parse_hex_number
                         , || pid))
              ~ eof
              , || (value, pid)));

/// Parse a stop-reply thread-exited packet.
named!(pub parse_stop_thread_exit<&[u8], (u8, u64)>,
       chain!(tag!("w")
              ~ value: parse_2_hex // FIXME more is ok!!?
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
       alt!(tag!("0") => { |_| Id::Any }
            | tag!("-1") => { |_| Id::All }
            | parse_hex_number => { |val: u64| Id::Id(val as u32) }));

/// Parse a thread-id.
named!(pub parse_thread_id<&[u8], ProcessId>,
       alt!(parse_thread_id_element => { |pid| ProcessId { pid: pid, tid: Id::Any } }
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
       alt!(tag!("l") => { |_| None }
            | parse_thread_id_list => { |v| Some(v) }));

/// Parse a `qSymbol` response.
named!(pub parse_qsymbol<&[u8], Option<Vec<u8>> >,
       alt!(tag!("OK") => { |_| None }
            | chain!(tag!("qSymbol:")
                     ~ data: parse_hex_data
                     , || { data }) => { |v| Some(v) }));

// not clear we want to bother with this
// named!(pub parse_packet_start<&[u8]> -> PacketType,
//        alt!(tag!("$") => { |_| PacketType::Normal }
//             | tag!("%") => { |_| PacketType::Notification }));

// named~(pub parse_packet<&[u8]>,
//        chain!(kind: parse_packet_start

