//! Perfetto trace file reader utilities.
//!
//! This module provides streaming iteration over TracePackets from Perfetto
//! protobuf trace files (.pb or .pb.gz).

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use perfetto_protos::trace_packet::TracePacket;
use protobuf::Message;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Iterator that streams TracePackets from a Perfetto trace file.
pub struct TracePacketIterator<R: BufRead> {
    reader: R,
    buffer: Vec<u8>,
}

impl<R: BufRead> TracePacketIterator<R> {
    /// Create a new TracePacketIterator from a reader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(64 * 1024),
        }
    }
}

impl<R: BufRead> Iterator for TracePacketIterator<R> {
    type Item = Result<TracePacket>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut tag_byte = [0u8; 1];
            match self.reader.read_exact(&mut tag_byte) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                Err(e) => return Some(Err(e.into())),
            }

            let wire_type = tag_byte[0] & 0x07;
            let field_number = tag_byte[0] >> 3;

            // Field 1 (packet), wire type 2 (length-delimited)
            if field_number == 1 && wire_type == 2 {
                let length = match read_varint(&mut self.reader) {
                    Ok(len) => len as usize,
                    Err(e) => return Some(Err(e)),
                };

                self.buffer.clear();
                if self.buffer.capacity() < length {
                    self.buffer.reserve(length - self.buffer.capacity());
                }
                self.buffer.resize(length, 0);

                if let Err(e) = self.reader.read_exact(&mut self.buffer) {
                    return Some(Err(e.into()));
                }

                return match TracePacket::parse_from_bytes(&self.buffer) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(e) => Some(Err(e.into())),
                };
            }

            // Skip non-packet fields
            if let Err(e) = skip_field(&mut self.reader, wire_type) {
                return Some(Err(e));
            }
        }
    }
}

/// Read a varint from a reader.
pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7f) as u64) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("Varint too large");
        }
    }
    Ok(result)
}

/// Skip a protobuf field based on its wire type.
pub fn skip_field<R: Read>(reader: &mut R, wire_type: u8) -> Result<()> {
    match wire_type {
        0 => {
            read_varint(reader)?;
        }
        1 => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
        }
        2 => {
            let len = read_varint(reader)? as usize;
            std::io::copy(&mut reader.take(len as u64), &mut std::io::sink())?;
        }
        5 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
        }
        _ => bail!("Unknown wire type: {wire_type}"),
    }
    Ok(())
}

/// Open a Perfetto trace file for reading, handling .gz compression.
pub fn open_trace_reader(path: &Path) -> Result<Box<dyn BufRead + Send>> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.ends_with(".gz") {
        let decoder = GzDecoder::new(reader);
        Ok(Box::new(BufReader::with_capacity(256 * 1024, decoder)))
    } else {
        Ok(Box::new(reader))
    }
}
