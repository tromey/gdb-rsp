use nom::*;
use nom::IResult::*;
use util::decode_hex;
use low::*;
use parse::*;

use std::io::Read;
use std::io::Write;

pub enum QueryOption<'conn> {
    Bool(bool),
    String(&'conn [u8]),
}

pub struct GdbRspClient<'conn> {
    conn: RspConnection<'conn>,
    non_stop: bool,
    require_acks: bool,
    current_thread: ProcessId,
    queries: Vec<(&'conn [u8], QueryOption<'conn>)>,
}

impl<'conn> GdbRspClient<'conn> {
    pub fn read_packet_with_retries(&mut self) -> RspResult<Vec<u8>> {
        loop {
            match self.conn.read_packet() {
                Ok((PacketType::Notification, contents)) => {
                    try!(self.dispatch_notification(contents));
                },
                Ok((PacketType::Normal, contents)) => {
                    return Ok(contents);
                },

                Err(RspError::InvalidChecksum) => {
                    // Keep going.
                },
                Err(value) => {
                    // FIXME handle io errors and TooManyRetries separately
                    return Err(value);
                }
            };
        }
    }

    fn read_simple_reply(&mut self) -> ClientResult<()> {
        // FIXME
        let contents = try!(self.read_packet_with_retries());

        match parse_simple_reply(&contents[..]) {
            Done(rest, response) => response,
            _ => Err(ClientError::Unrecognized),
        }
    }

    // fn send_qsupported(&mut self) {
    //     try!(self.conn.start_packet());
    //     try!(self.conn.write_all(b"qSupported"));
    //     let mut prefix = b":";
    //     for feature in self.queries {
    //         let (name, value) = feature;
    //         try!(self.conn.write_all(prefix));
    //         prefix = b";";

    //         try!(self.conn.write_all(name));
    //         match value {
    //             QueryOption::Bool(true) => {
    //                 try!(self.conn.write_all(b"+"));
    //             },
    //             QueryOption::Bool(false) => {
    //                 try!(self.conn.write_all(b"-"));
    //             },
    //             QueryOption::String(str) => {
    //                 try!(self.conn.write_all(str));
    //             },
    //         };
    //     }
    //     try!(self.conn.finish_packet())

    //     // fixme the repsonse
    // }

    fn disable_acking(&mut self) -> ClientResult<()> {
        self.conn.full_packet(b"QStartNoAckMode");
        match self.read_simple_reply() {
            Ok(_) => {
                self.conn.disable_acking();
                Ok(())
            },
            v => v
        }
    }

    pub fn extended_mode(&mut self) -> ClientResult<()> {
        try!(self.conn.full_packet(b"!"));
        self.read_simple_reply()
    }

    pub fn query_supported(&mut self) {
    }

    pub fn startup(&mut self) {
        if !self.require_acks {
            self.disable_acking();
        }
    }

    pub fn new(reader: &'conn mut Read, writer: &'conn mut Write)
               -> GdbRspClient<'conn> {
        let queries = Vec::<(&'conn [u8], QueryOption<'conn>)>::new();
        queries.push((b"multiprocess", QueryOption::Bool(true)));
        queries.push((b"swbreak", QueryOption::Bool(true)));
        queries.push((b"hwbreak", QueryOption::Bool(true)));
        queries.push((b"fork-events", QueryOption::Bool(true)));
        queries.push((b"vfork-events", QueryOption::Bool(true)));
        queries.push((b"exec-events", QueryOption::Bool(true)));
        queries.push((b"vContSupported", QueryOption::Bool(true)));
        queries.push((b"QThreadEvents", QueryOption::Bool(true)));
        queries.push((b"no-resumed", QueryOption::Bool(true)));

        let conn = RspConnection::new(reader, writer, true);
        GdbRspClient { conn: conn,
                       non_stop: false,
                       require_acks: false,
                       current_thread: ProcessId { pid: Id::Any,
                                                   tid: Id::Any },
                       queries: queries,
        }
    }

    pub fn detach(&mut self, pid: Option<ProcessId>) -> ClientResult<()> {
        if let Some(value) = pid {
            try!(self.conn.start_packet());
            try!(self.conn.write_all(b"D;"));
            try!(self.conn.write_thread_id(value));
            try!(self.conn.finish_packet());
        } else {
            try!(self.conn.full_packet(b"D"));
        }
        self.read_simple_reply()
    }

    pub fn query_stop_reason(&mut self) {
        try!(self.conn.full_packet(b"?"));
        // parse_stop_reply();
    }

    fn maybe_set_thread(&mut self, thread: ProcessId) {
        if self.current_thread != thread {
            // b"Hg" id
        }
    }

    pub fn read_memory(&mut self, addr: u64, length: u64)
                       -> ClientResult<Vec<u8>> {
        // m addr , length
        try!(self.conn.start_packet());
        try!(write!(self.conn, "m{:x},{:x}", addr, length));
        try!(self.conn.finish_packet());
        let contents = try!(self.read_packet_with_retries());
        match parse_memory(&contents[..]) {
            Done(rest, response) => response,
            _ => Err(ClientError::Unrecognized)
        }
    }

    pub fn write_memory(&mut self, addr: u64, data: &[u8]) {
        // if self.packet_ok(X_packet) {
        //     self.conn.start_packet();
        //     self.conn.write_all(b"X");
        //     self.conn.write_number(addr);
        //     self.conn.write_all(b",");
        //     self.conn.write_number(data.len());
        //     self.conn.write_all(b":");
        //     self.conn.write_binary(data);
            
        //     let something = self.normal_reply(X_packet);
        // }
        // if something == ClientResult<()>::Unsupported {
        //     self.conn.start_packet();
        //     self.conn.write_all(b"M");
        //     self.conn.write_number(addr);
        //     self.conn.write_all(b",");
        //     self.conn.write_number(data.len());
        //     self.conn.write_all(b":");
        //     self.conn.write_hex(data);

        //     let something = self.normal_reply(X_packet);
        // }

        // Fail(blah)
    }

    pub fn read_register(&mut self, register: u64)-> ClientResult<()> {
        try!(self.conn.start_packet());
        try!(write!(self.conn, "p{:x}=", register));
        try!(self.conn.finish_packet());
        // alt_complete!(eof => { |_| Unsupported }
        //               | parse_error => { |e| Error(e) }
        //               | parse_hex_data => { |v| RegisterValue(v) })
    }

    pub fn write_register(&mut self, register: u64, value: &[u8])
                          -> ClientResult<()> {
        // FIXME the 'P' packet isn't required to be supported
        try!(self.conn.start_packet());
        try!(write!(self.conn, "P{:x}=", register));
        try!(self.conn.write_all(value));
        try!(self.conn.finish_packet());
        self.read_simple_reply()
    }

    pub fn ping_thread(&mut self, thread: ProcessId) -> ClientResult<()> {
        try!(self.conn.start_packet());
        try!(self.conn.write_all(b"T"));
        try!(self.conn.write_thread_id(thread));
        try!(self.conn.finish_packet());
        self.read_simple_reply()
    }

    fn vpacket(&mut self, cmd: &[u8], pid: ProcessId)-> ClientResult<()> {
        try!(self.conn.start_packet());
        try!(self.conn.write_all(cmd));
        try!(self.conn.write_thread_id(pid));
        try!(self.conn.finish_packet());
        // stop reply
    }

    pub fn attach(&mut self, pid: ProcessId) -> ClientResult<()> {
        // returns a stop packet
        // differences in all/non-stop
        self.vpacket(b"vAttach;", pid)
    }

    pub fn kill(&mut self, pid: ProcessId) -> ClientResult<()> {
        // returns a stop packet
        // differences in all/non-stop
        self.vpacket(b"vKill;", pid)
    }

    pub fn cont() {
    }

    fn set_or_clear_breakpoint(&mut self, cmd: &[u8], addr: u64,
                               kind: Option<u8>) -> ClientResult<()> {
        let size = match kind {
            Some(value) => value,
            None => 0,
        };
        try!(self.conn.start_packet());
        try!(self.conn.write_all(cmd));
        // FIXME what is the real approach for SIZE?
        try!(write!(self.conn, ",{:x},{}", addr, size));
        try!(self.conn.finish_packet());
        self.read_simple_reply()
    }

    // FIXME - no way to set conditions
    pub fn set_software_breakpoint(&mut self, addr: u64, kind: Option<u8>)
                                   -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"Z0", addr, kind)
    }

    pub fn clear_software_breakpoint(&mut self, addr: u64, kind: Option<u8>)
                                     -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"z0", addr, kind)
    }

    pub fn set_hardware_breakpoint(&mut self, addr: u64, kind: Option<u8>)
                                   -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"Z1", addr, kind)
    }

    pub fn clear_hardware_breakpoint(&mut self, addr: u64, kind: Option<u8>)
                                     -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"z1", addr, kind)
    }

    pub fn set_write_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                                -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"Z2", addr, kind)
    }

    pub fn clear_write_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                                  -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"z2", addr, kind)
    }

    pub fn set_read_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                               -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"Z3", addr, kind)
    }

    pub fn clear_read_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                                 -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"z3", addr, kind)
    }

    pub fn set_access_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                                 -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"Z4", addr, kind)
    }

    pub fn clear_access_watchpoint(&mut self, addr: u64, kind: Option<u8>)
                                   -> ClientResult<()> {
        self.set_or_clear_breakpoint(b"z4", addr, kind)
    }

    pub fn set_randomization(&mut self, state: bool) -> ClientResult<()> {
        if state {
            try!(self.conn.full_packet(b"QDisableRandomization:1"));
        } else {    
            try!(self.conn.full_packet(b"QDisableRandomization:0"));
        }
        self.read_simple_reply()
    }

    pub fn set_nonstop(&mut self, state: bool) -> ClientResult<()> {
        if state {
            try!(self.conn.full_packet(b"QNonStop:1"));
        } else {    
            try!(self.conn.full_packet(b"QNonStop:0"));
        }
        let result = self.read_simple_reply();
        if let Ok(blah) = result {
            self.non_stop = state;
        }
        result
    }

    pub fn set_thread_events(&mut self, state: bool) -> ClientResult<()> {
        if state {
            try!(self.conn.full_packet(b"QThreadEvents:1"));
        } else {    
            try!(self.conn.full_packet(b"QThreadEvents:0"));
        }
        self.read_simple_reply()
    }

    fn signal_op(&mut self, command: &[u8], signals: &[u8])
                 -> ClientResult<()> {
        let mut signals = signals.clone();
        signals.sort();
        try!(self.conn.start_packet());
        try!(self.conn.write_all(command));
        let mut separator = b":";
        for sig in signals.into_iter() {
            try!(self.conn.write_all(separator));
            separator = b";";

            try!(write!(self.conn, "{:x}", *sig));
        }
        try!(self.conn.finish_packet());
        self.read_simple_reply()
    }

    pub fn set_pass_signals(&mut self, signals: &[u8])
                            -> ClientResult<()> {
        self.signal_op(b"QPassSignals", signals)
    }

    pub fn set_program_signals(&mut self, signals: &[u8])
                               -> ClientResult<()> {
        self.signal_op(b"QProgramSignals", signals)
    }

    pub fn catch_syscalls(&mut self, syscalls: Option<&[u8]>)
                          -> ClientResult<()> {
        if let Some(calls) = syscalls {
            try!(self.conn.start_packet());
            try!(self.conn.write_all(b"QCatchSyscalls:1"));
            for call in calls {
                try!(write!(self.conn, ";{:x}", call));
            }
            try!(self.conn.finish_packet());
        } else {
            // Disable.
            try!(self.conn.full_packet(b"QCatchSyscalls:0"));
        }
        self.read_simple_reply()
    }

    pub fn send_qsymbol(&mut self, symbol: Option<(&[u8], u64)>) -> RspResult<Option<Vec<u8>>> {
        try!(self.conn.start_packet());
        try!(self.conn.write_all(b"qSymbol:"));
        match symbol {
            None => try!(self.conn.write_all(b":")),
            Some((name, addr)) => {
                try!(write!(self.conn, "{:x}:", addr));
                try!(self.conn.write_all(name));
            },
        };
        try!(self.conn.finish_packet());
        let result = try!(self.read_packet_with_retries());
        parse_qsymbol(result)
    }
}
