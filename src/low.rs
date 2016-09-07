#![deny(missing_docs)]

use std::io;
use std::io::Write;

/// A low-level error that occurred when communicating over the RSP
/// connection.
pub enum RspError {
    /// A wrapped I/O error.
    IOError(io::Error),
    /// A packet was received that had an invalid checksum.  Note that
    /// checksums are only checked in "ack" mode; if `QStartNoAckMode`
    /// is used, then acking and checksum checking are disabled.
    InvalidChecksum,
    /// A packet started with a character other than '$' or '%'.
    InvalidPacketType(u8),
}

/// The result of a RSP request.
pub type RspResult<T> = Result<T, RspError>;

/// Part of a process id.
#[derive(Clone, Copy)]
pub enum Id {
    /// A process or thread id.  This value may not be 0 or -1.
    Id(u32),
    /// A special form meaning all processes or all threads of a given
    /// process.
    All,
    /// A special form meaning any process or any thread of a given
    /// process.
    Any,
}

/// A process identifier.  In the RSP this is just a numeric handle
/// that is passed across the wire.  It needn't correspond to any real
/// process id (though obviously it may be more convenient when it
/// does).
#[derive(Clone, Copy)]
pub struct ProcessId {
    /// The process id.
    pub pid: Id,
    /// The thread id.
    pub tid: Id,
}

impl ProcessId {
    /// Make a new process/thread id.  |pid| is the process id; it
    /// must be greater than or equal to zero.  |tid|, if given, is
    /// the thread id.
    pub fn new(pid: i32, tid: Option<i32>) -> ProcessId {
        assert!(pid > 0);
        let mut result = ProcessId { pid: Id::Id(pid as u32), tid: Id::Any };
        match tid {
            Some(value) => {
                assert!(value > 0);
                result.tid = Id::Id(value as u32);
            }
            None => { }
        }
        result
    }
}

// fixme -
// multiprocess mode
// maximum # retries
/// An RSP connection.  This can represent either the client- or
/// server- side of an RSP connection, and holds channels for sending
/// to and receiving data from the other side of the connection.  It
/// manages various low-level tasks, such as sending acks; and
/// supplies a number of convenience methods for constructing and
/// parsing RSP packets.
pub struct RspConnection<'conn> {
    wchan: &'conn mut io::Write,
    rchan: &'conn mut io::Read,

    // True if we must ack packets.
    acking: bool,

    // At least decide about RLE.
    // FIXME our server side doesn't implement RLE yet.
    is_client: bool,

    // If 0, not in a packet; otherwise holds the packet type.
    in_packet: u8,

    // Checksum of the packet currently being constructed.
    checksum: u8,

    // When acking we must keep the last packet around.
    last_packet: Vec<u8>,
}

impl<'conn> io::Write for RspConnection<'conn> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = self.wchan.write(buf);
        if let Ok(nbytes) = result {
            for i in 0..nbytes {
                self.checksum = self.checksum.wrapping_add(buf[i]);
            }
            if self.acking {
                self.last_packet.extend_from_slice(&buf[0..nbytes]);
            }
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.wchan.flush()
    }
}

// Ensure we can use try! to turn an io::Error into an RspError.
impl From<io::Error> for RspError {
    fn from(t: io::Error) -> Self {
        RspError::IOError(t)
    }
}

impl<'conn> RspConnection<'conn> {
    /// Create a new `RspConnection`.  `is_client` is `True` if this
    /// object should be an RSP client, or `False` if this object
    /// should be an RSP server.  (The two halves differ in some
    /// protocol details.)  The reader and writer should already be
    /// connected to the other side.
    pub fn new(reader: &'conn mut io::Read, writer: &'conn mut io::Write, is_client: bool) -> RspConnection<'conn> {
        RspConnection {
            wchan: writer,
            rchan: reader,
            acking: true,
            is_client: is_client,
            in_packet: 0,
            checksum: 0,
            last_packet: Vec::new(),
        }
    }

    /// Start a new packet.  The caller is responsible for the entire
    /// contents of the packet, but the framing is handled by this
    /// object.  Call `finish_packet` when the packet contents are
    /// fully written; it's an error to start a new packet before the
    /// current packet is finished.
    pub fn start_packet(&mut self) -> RspResult<()> {
        assert!(self.in_packet == 0);
        self.checksum = 0;
        self.in_packet = b'$';
        // Bypass the checksumming.
        try!(self.wchan.write_all(b"$"));
        Ok(())
    }

    /// Start a new notification packet.  The caller is responsible
    /// for the entire contents of the packet, but the framing is
    /// handled by this object.  Call `finish_packet` when the packet
    /// contents are fully written; it's an error to start a new
    /// packet before the current packet is finished.
    ///
    /// Note that while notifications are defined for both sides of
    /// the protocol, in practice they are only emitted by servers.
    pub fn start_notification_packet(&mut self) -> RspResult<()> {
        assert!(self.in_packet == 0);
        self.checksum = 0;
        self.in_packet = b'%';
        // Bypass the checksumming.
        try!(self.wchan.write_all(b"%"));
        Ok(())
    }

    /// Finish a packet.  Either `start_packet` or
    /// `start_notification_packet` must have been called previously.
    ///
    /// When the `RspConnection` is in acking mode, this method will
    /// read an ack, and will resend the current packet until acked.
    ///
    /// Note that this method does not read any other reply from the
    /// remote.  That is, on the client side, `read_packet` must be
    /// called to read the reply; and on the server side, some
    /// as-yet-unwritten (FIXME) method must be called to read the
    /// response to a notification.
    pub fn finish_packet(&mut self) -> RspResult<()> {
        assert!(self.in_packet != 0);
        let kind = self.in_packet;
        self.in_packet = 0;
        // Bypass the checksumming.
        try!(write!(self.wchan, "#{:02x}", self.checksum));

        if self.acking {
            loop {
                let ch = try!(self.read_char());
                if ch == b'+' {
                    break;
                }

                let buf = [kind];
                try!(self.wchan.write_all(&buf));
                try!(self.wchan.write_all(&self.last_packet));
                try!(write!(self.wchan, "#{:02x}", self.checksum));
            }

            self.last_packet.clear();
        }

        Ok(())
    }

    /// A convenience function that sends an entire packet at once.
    /// This simply calls `start_packet`, `write_all` with the
    /// contents, and then `finish_packet`.
    pub fn full_packet(&mut self, contents: &[u8]) -> RspResult<()> {
        try!(self.start_packet());
        try!(self.write_all(contents));
        self.finish_packet()
    }

    /// Disable acking mode on this object.
    ///
    /// Note that this can only be done by coordination with the other
    /// end of the connection, in particular using `QStartNoAckMode`,
    /// which is not done here.  Calling this method without this
    /// handshake will cause communication failures.
    pub fn disable_acking(&mut self) {
        self.acking = false;
        // Free any memory taken by the previous vec.
        self.last_packet = Vec::new();
    }

    /// Write some binary data into an open packet, using the "new"
    /// 8-bit-clean binary interface.  Check the details of the
    /// protocol message you are sending to ensure this makes sense;
    /// and see `write_hex` as well.  `buf` is the raw data to write;
    /// this method takes care of any quoting that may be necessary.
    pub fn write_binary(&mut self, buf: &[u8]) -> RspResult<()> {
        assert!(self.in_packet != 0);

        let mut last_index = 0;

        for i in 0..buf.len() {
            match buf[i] {
                // It doesn't hurt to always escape "*", and this lets
                // the code work for both the client and the server.
                b'$' | b'#' | b'}' | b'*' => {
                    if i > last_index {
                        try!(self.write_all(&buf[last_index..i]));
                        last_index = i + 1;
                    }
                    let bytes = [b'}', buf[i] ^ 0x20];
                    try!(self.write_all(&bytes));
                }
                _ => {
                    // Ignore, it will be caught next time we have to
                    // escape, or at the end.
                }
            }
        }

        if buf.len() >= last_index {
            try!(self.write_all(&buf[last_index..]));
        }

        Ok(())
    }

    /// Write some binary data into an open packet, using the old hex
    /// interface -- each byte is written as two hex digits.  Check
    /// the details of the protocol message you are sending to ensure
    /// this makes sense; and see `write_binary` as well.
    pub fn write_hex(&mut self, data: &[u8]) -> RspResult<()> {
        assert!(self.in_packet != 0);

        for elt in data.iter() {
            try!(write!(self, "{:02x}", elt));
        }
        Ok(())
    }

    /// Write a "thread-id" into an open packet.
    pub fn write_thread_id(&mut self, pid: ProcessId) -> RspResult<()> {
        // FIXME when not in multiprocess mode...
        // but maybe this library should be opinionated.

        try!(self.write_all(b"p"));
        match pid.pid {
            Id::Id(val) => {
                try!(write!(self, "{:x}.", val.to_be()));
                match pid.tid {
                    Id::Id(val) => try!(write!(self, "{:x}", val.to_be())),
                    Id::All => try!(self.write_all(b"-1")),
                    Id::Any => try!(self.write_all(b"0")),
                };
            },
            Id::All => try!(self.write_all(b"-1")),
            Id::Any => try!(self.write_all(b"0")),
        };

        Ok(())
    }

    /// Send the low-level interrupt, 0x03, to the server.  This is
    /// not valid when a packet has been opened (e.g., between
    /// `start_packet` and `finish_packet`).  It is also only valid to
    /// call this on the client.
    pub fn interrupt(&mut self) -> RspResult<()> {
        assert!(self.in_packet == 0);
        assert!(self.is_client);
        try!(self.wchan.write_all(b"\x03"));
        Ok(())
    }

    // Get a single character from the read channel.
    fn read_char(&mut self) -> RspResult<u8> {
        let mut buf = [0u8];
        match self.rchan.read_exact(&mut buf) {
            Err(e) => Err(RspError::IOError(e)),
            Ok(_) => Ok(buf[0]),
        }
    }

    // Decode a single hex character.
    fn decode_hex(c: u8) -> Option<u8> {
        match c {
            b'0'...b'9' => Some(c - b'0'),
            b'a'...b'f' => Some(c - b'a' + 10),
            b'A'...b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    /// Read a packet.  A normal result consists of a tuple of two
    /// elements; the first element being the packet type, either b'$'
    /// for a normal packet, or b'%' for a notification; and the
    /// second element being the packet contents.
    ///
    /// The contents are mostly just raw bytes; however, if any RLE
    /// encoding was done on the wire, it is expanded in the result.
    ///
    /// In acking mode, this method will send the ack.  However, it
    /// does not try to re-read (FIXME??), but instead simply returns
    /// `InvalidChecksum` when the checksum does not match.
    pub fn read_packet(&mut self) -> RspResult<(u8, Vec<u8>)> {
        let kind = try!(self.read_char());
        if kind != b'$' && kind != b'%' {
            return Err(RspError::InvalidPacketType(kind));
        }
        
        let mut contents = Vec::new();
        let mut checksum: u8 = 0;
        let mut prev_ch = b'$';

        loop {
            let ch = try!(self.read_char());
            match ch {
                b'#' => {
                    break;
                }

                b'*' if self.is_client => {
                    // RLE decoding.
                    let repeat_ch = try!(self.read_char());
                    let repeat = repeat_ch - 29;

                    for _ in 0..repeat {
                        contents.push(prev_ch);
                    }
                    // FIXME should report an error if we see "*"
                    // without a preceding character.
                    prev_ch = b'$';

                    checksum = checksum.wrapping_add(b'*');
                    checksum = checksum.wrapping_add(repeat_ch);
                }

                _ => {
                    contents.push(ch);
                    checksum = checksum.wrapping_add(ch);
                    prev_ch = ch;
                }
            }
        }

        let n1 = Self::decode_hex(try!(self.read_char()));
        let n2 = Self::decode_hex(try!(self.read_char()));

        // Only bother with checksum verification in acking mode.
        // This is a little sad maybe, but the manual says this is ok,
        // so we assume that some clients might not even bother
        // computing the checksum properly in this case (though
        // there's no evidence any actually does so).
        if self.acking {
            let n = match (n1, n2) {
                (Some(v1), Some(v2)) => v1 * 16 + v2,
                // Pick an invalid value if we can't decode the checksum.
                _ => !checksum,
            };

            if n == checksum {
                try!(self.wchan.write_all(b"+"))
            } else {
                try!(self.wchan.write_all(b"-"));
                return Err(RspError::InvalidChecksum);
            }
        }

        Ok((kind, contents))
    }
}
