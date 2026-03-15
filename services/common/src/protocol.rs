use crate::error::TorError;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Type aliases for IDs
pub type CircuitId = u32;
pub type StreamId = u16;

/// Fixed cell size in bytes (every message on the wire is exactly this size).
/// Matches real Tor's 514-byte cell size.
pub const CELL_SIZE: usize = 514;

/// Header size: Length(4) + CircuitId(4) + StreamId(2) + Command(1) = 11 bytes
pub const HEADER_SIZE: usize = 11;

/// Size of the payload-length prefix inside the data region (u16 = 2 bytes)
pub const PAYLOAD_LEN_SIZE: usize = 2;

/// Size of the running SHA-256 digest field (4 bytes, matching real Tor)
pub const DIGEST_SIZE: usize = 4;

/// Maximum usable payload per cell: CELL_SIZE - HEADER_SIZE - PAYLOAD_LEN_SIZE - DIGEST_SIZE = 497 bytes
pub const MAX_PAYLOAD_SIZE: usize = CELL_SIZE - HEADER_SIZE - PAYLOAD_LEN_SIZE - DIGEST_SIZE;

/// Message commands for the Tor protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageCommand {
    // Circuit-level commands
    Create = 0x01,
    Created = 0x02,
    Extend = 0x03,
    Extended = 0x04,
    Destroy = 0x05,

    // Stream-level commands
    Begin = 0x10,
    Connected = 0x11,
    Data = 0x12,
    End = 0x13,
}

impl MessageCommand {
    /// Convert from u8 byte value
    ///
    /// # Errors
    /// Returns an error if the byte value doesn't match any known command
    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0x01 => Ok(MessageCommand::Create),
            0x02 => Ok(MessageCommand::Created),
            0x03 => Ok(MessageCommand::Extend),
            0x04 => Ok(MessageCommand::Extended),
            0x05 => Ok(MessageCommand::Destroy),
            0x10 => Ok(MessageCommand::Begin),
            0x11 => Ok(MessageCommand::Connected),
            0x12 => Ok(MessageCommand::Data),
            0x13 => Ok(MessageCommand::End),
            _ => Err(format!("Unknown message command: 0x{:02x}", value)),
        }
    }

    /// Convert to u8 byte value
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for MessageCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageCommand::Create => write!(f, "CREATE"),
            MessageCommand::Created => write!(f, "CREATED"),
            MessageCommand::Extend => write!(f, "EXTEND"),
            MessageCommand::Extended => write!(f, "EXTENDED"),
            MessageCommand::Destroy => write!(f, "DESTROY"),
            MessageCommand::Begin => write!(f, "BEGIN"),
            MessageCommand::Connected => write!(f, "CONNECTED"),
            MessageCommand::Data => write!(f, "DATA"),
            MessageCommand::End => write!(f, "END"),
        }
    }
}

/// Wire protocol message
///
/// Fixed-size 514-byte cell layout:
/// ```text
/// [Length: 4B | CircuitId: 4B | StreamId: 2B | Command: 1B | PayloadLen: 2B | Digest: 4B | Data+Padding: 497B]
/// ```
///
/// - Length field is always 510 (= 514 - 4), the number of bytes after the length field.
/// - PayloadLen (u16 BE) stores the actual data size (0..497).
/// - Digest (4 bytes) is the first 4 bytes of a running SHA-256 snapshot for integrity
///   verification. Set to `[0; 4]` for handshake messages (CREATE, CREATED, EXTEND, EXTENDED)
///   which are not digest-protected.
/// - Data is followed by zero-padding to fill exactly 497 bytes.
/// - The PayloadLen prefix is critical because raw data (e.g. X25519 keys) may end in 0x00.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    // Routing
    pub circuit_id: CircuitId,
    pub stream_id: StreamId,

    // Content
    pub command: MessageCommand,
    pub data: Vec<u8>,

    // Integrity
    pub digest: [u8; 4],
}

impl Message {
    /// Create a new message with digest set to zero (caller must set digest before sending)
    pub fn new(
        circuit_id: CircuitId,
        stream_id: StreamId,
        command: MessageCommand,
        data: Vec<u8>,
    ) -> Self {
        Self {
            circuit_id,
            stream_id,
            command,
            data,
            digest: [0u8; 4],
        }
    }

    /// Create a circuit-level message (stream_id = 0)
    pub fn circuit(circuit_id: CircuitId, command: MessageCommand, data: Vec<u8>) -> Self {
        Self::new(circuit_id, 0, command, data)
    }

    /// Create a stream-level message
    pub fn stream(
        circuit_id: CircuitId,
        stream_id: StreamId,
        command: MessageCommand,
        data: Vec<u8>,
    ) -> Self {
        Self::new(circuit_id, stream_id, command, data)
    }

    // Circuit-level message constructors

    /// Create a CREATE message with public key
    pub fn create(circuit_id: CircuitId, public_key: Vec<u8>) -> Self {
        Self::circuit(circuit_id, MessageCommand::Create, public_key)
    }

    /// Create a CREATED message with public key
    pub fn created(circuit_id: CircuitId, public_key: Vec<u8>) -> Self {
        Self::circuit(circuit_id, MessageCommand::Created, public_key)
    }

    /// Create an EXTEND message with encrypted payload
    pub fn extend(circuit_id: CircuitId, encrypted_payload: Vec<u8>) -> Self {
        Self::circuit(circuit_id, MessageCommand::Extend, encrypted_payload)
    }

    /// Create an EXTENDED message with response data
    pub fn extended(circuit_id: CircuitId, response_data: Vec<u8>) -> Self {
        Self::circuit(circuit_id, MessageCommand::Extended, response_data)
    }

    /// Create a DESTROY message
    pub fn destroy(circuit_id: CircuitId) -> Self {
        Self::circuit(circuit_id, MessageCommand::Destroy, vec![])
    }

    /// Create a BEGIN message with destination address
    pub fn begin(circuit_id: CircuitId, stream_id: StreamId, destination: Vec<u8>) -> Self {
        Self::stream(circuit_id, stream_id, MessageCommand::Begin, destination)
    }

    /// Create a CONNECTED message
    pub fn connected(circuit_id: CircuitId, stream_id: StreamId) -> Self {
        Self::stream(circuit_id, stream_id, MessageCommand::Connected, vec![])
    }

    /// Create a DATA message with payload
    pub fn data(circuit_id: CircuitId, stream_id: StreamId, payload: Vec<u8>) -> Self {
        Self::stream(circuit_id, stream_id, MessageCommand::Data, payload)
    }

    /// Create an END message with optional reason
    pub fn end(circuit_id: CircuitId, stream_id: StreamId, reason: Vec<u8>) -> Self {
        Self::stream(circuit_id, stream_id, MessageCommand::End, reason)
    }

    /// Serialize to fixed-size 514-byte cell.
    ///
    /// Layout: `[Length(4) | CircuitId(4) | StreamId(2) | Command(1) | PayloadLen(2) | Digest(4) | Data+Pad(497)]`
    ///
    /// If `self.data` exceeds `MAX_PAYLOAD_SIZE` (497), the data is silently truncated.
    /// Use `write_to_stream()` in production code for a checked version.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut cell = vec![0u8; CELL_SIZE];

        // Byte offset constants for the cell layout
        const DATA_START: usize = HEADER_SIZE + PAYLOAD_LEN_SIZE + DIGEST_SIZE; // 11+2+4 = 17

        // Length field (4 bytes): always CELL_SIZE - 4 = 510
        let length = (CELL_SIZE - 4) as u32;
        if let Some(s) = cell.get_mut(0..4) {
            s.copy_from_slice(&length.to_be_bytes());
        }

        // Circuit ID (4 bytes)
        if let Some(s) = cell.get_mut(4..8) {
            s.copy_from_slice(&self.circuit_id.to_be_bytes());
        }

        // Stream ID (2 bytes)
        if let Some(s) = cell.get_mut(8..10) {
            s.copy_from_slice(&self.stream_id.to_be_bytes());
        }

        // Command (1 byte)
        if let Some(slot) = cell.get_mut(10) {
            *slot = self.command.to_u8();
        }

        // Payload length (2 bytes) — actual data size (capped at MAX_PAYLOAD_SIZE)
        let data_len = self.data.len().min(MAX_PAYLOAD_SIZE);
        let payload_len = data_len as u16;
        if let Some(s) = cell.get_mut(11..13) {
            s.copy_from_slice(&payload_len.to_be_bytes());
        }

        // Digest (4 bytes)
        if let Some(s) = cell.get_mut(13..17) {
            s.copy_from_slice(&self.digest);
        }

        // Data (up to MAX_PAYLOAD_SIZE bytes) — rest stays zero-padded
        if let Some(dest) = cell.get_mut(DATA_START..DATA_START + data_len)
            && let Some(src) = self.data.get(..data_len)
        {
            dest.copy_from_slice(src);
        }

        cell
    }

    /// Deserialize from a fixed-size 514-byte cell.
    ///
    /// Reads the 2-byte payload_len prefix and the 4-byte digest field, then
    /// extracts exactly `payload_len` data bytes, ignoring the zero-padding.
    ///
    /// # Errors
    /// Returns an error if the buffer is too small, the length field is wrong,
    /// the command byte is invalid, or the payload length exceeds the data region.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Byte offset where data starts
        const DATA_START: usize = HEADER_SIZE + PAYLOAD_LEN_SIZE + DIGEST_SIZE; // 17

        if bytes.len() < CELL_SIZE {
            return Err(format!(
                "Cell too short: {} bytes (expected {})",
                bytes.len(),
                CELL_SIZE
            ));
        }

        // Parse length (4 bytes) — must be 510
        let length_bytes: [u8; 4] = bytes
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete cell: missing length")?;
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length != CELL_SIZE - 4 {
            return Err(format!(
                "Invalid cell length field: {} (expected {})",
                length,
                CELL_SIZE - 4
            ));
        }

        // Parse circuit ID (4 bytes)
        let circuit_bytes: [u8; 4] = bytes
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete cell: missing circuit ID")?;
        let circuit_id = u32::from_be_bytes(circuit_bytes);

        // Parse stream ID (2 bytes)
        let stream_bytes: [u8; 2] = bytes
            .get(8..10)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete cell: missing stream ID")?;
        let stream_id = u16::from_be_bytes(stream_bytes);

        // Parse command (1 byte)
        let command_byte = bytes.get(10).ok_or("Incomplete cell: missing command")?;
        let command = MessageCommand::from_u8(*command_byte)?;

        // Parse payload length (2 bytes)
        let payload_len_bytes: [u8; 2] = bytes
            .get(11..13)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete cell: missing payload length")?;
        let payload_len = u16::from_be_bytes(payload_len_bytes) as usize;

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(format!(
                "Payload length {} exceeds maximum {}",
                payload_len, MAX_PAYLOAD_SIZE
            ));
        }

        // Parse digest (4 bytes)
        let digest_bytes: [u8; 4] = bytes
            .get(13..17)
            .and_then(|s| s.try_into().ok())
            .ok_or("Incomplete cell: missing digest")?;

        // Extract exactly payload_len bytes of data (ignore padding)
        let data = bytes
            .get(DATA_START..DATA_START + payload_len)
            .ok_or("Incomplete cell: data region too short")?
            .to_vec();

        Ok(Self {
            circuit_id,
            stream_id,
            command,
            data,
            digest: digest_bytes,
        })
    }

    /// Read a message from a blocking stream.
    ///
    /// Reads exactly `CELL_SIZE` (514) bytes, then parses.
    ///
    /// # Errors
    /// Returns IO errors if reading fails or if the cell format is invalid
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; CELL_SIZE];
        reader.read_exact(&mut buf)?;

        Self::from_bytes(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Read a message from an async stream.
    ///
    /// Reads exactly `CELL_SIZE` (514) bytes in one shot, then parses.
    /// Returns `None` if the connection was closed gracefully (EOF on first read).
    ///
    /// # Errors
    /// Returns IO errors if reading fails or if the cell format is invalid
    pub async fn from_stream<S>(stream: &mut S) -> io::Result<Option<Self>>
    where
        S: tokio::io::AsyncReadExt + Unpin,
    {
        let mut buf = [0u8; CELL_SIZE];

        // Read exactly CELL_SIZE bytes; EOF on the very first byte means graceful close
        match stream.read_exact(&mut buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None); // Connection closed
            }
            Err(e) => return Err(e),
        }

        Self::from_bytes(&buf)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write this message to an async stream as a fixed-size 514-byte cell.
    ///
    /// This is the checked production path: it returns `PayloadTooLarge` if
    /// `self.data.len()` exceeds `MAX_PAYLOAD_SIZE` (501 bytes).
    ///
    /// # Errors
    /// Returns `TorError::PayloadTooLarge` if data exceeds the limit, or an IO error
    /// if writing fails.
    pub async fn write_to_stream<S>(&self, stream: &mut S) -> Result<(), TorError>
    where
        S: tokio::io::AsyncWriteExt + Unpin,
    {
        if self.data.len() > MAX_PAYLOAD_SIZE {
            return Err(TorError::PayloadTooLarge {
                size: self.data.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let cell = self.to_bytes();
        stream.write_all(&cell).await?;
        Ok(())
    }

    /// Write a message to a blocking stream as a fixed-size 514-byte cell.
    ///
    /// # Errors
    /// Returns IO errors if writing or flushing fails
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let cell = self.to_bytes();
        writer.write_all(&cell)?;
        writer.flush()
    }

    /// Total wire size of a cell (always `CELL_SIZE` = 514 bytes)
    pub fn size(&self) -> usize {
        CELL_SIZE
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_message_command_conversion() {
        assert_eq!(
            MessageCommand::from_u8(0x01).unwrap(),
            MessageCommand::Create
        );
        assert_eq!(MessageCommand::from_u8(0x12).unwrap(), MessageCommand::Data);
        assert!(MessageCommand::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::new(12345, 678, MessageCommand::Data, vec![1, 2, 3, 4, 5]);

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);

        let msg2 = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg.circuit_id, msg2.circuit_id);
        assert_eq!(msg.stream_id, msg2.stream_id);
        assert_eq!(msg.command, msg2.command);
        assert_eq!(msg.data, msg2.data);
    }

    #[test]
    fn test_message_wire_format() {
        let msg = Message::circuit(100, MessageCommand::Create, vec![0xAA, 0xBB]);

        let bytes = msg.to_bytes();

        // Always CELL_SIZE bytes
        assert_eq!(bytes.len(), CELL_SIZE);

        // Length field: always 510 (= 514 - 4)
        assert_eq!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            510
        );

        // Circuit ID
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            100
        );

        // Stream ID
        assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 0);

        // Command
        assert_eq!(bytes[10], MessageCommand::Create.to_u8());

        // Payload length (2 bytes of actual data)
        assert_eq!(u16::from_be_bytes([bytes[11], bytes[12]]), 2);

        // Digest (4 bytes, all zero for new message)
        assert_eq!(bytes[13], 0);
        assert_eq!(bytes[14], 0);
        assert_eq!(bytes[15], 0);
        assert_eq!(bytes[16], 0);

        // Data starts at byte 17
        assert_eq!(bytes[17], 0xAA);
        assert_eq!(bytes[18], 0xBB);

        // Padding (remaining bytes should be zero)
        for &b in &bytes[19..CELL_SIZE] {
            assert_eq!(b, 0, "Padding byte should be zero");
        }
    }

    #[test]
    fn test_message_read_write() {
        use std::io::Cursor;

        let msg = Message::stream(999, 42, MessageCommand::Begin, b"example.com:80".to_vec());

        let mut buffer = Vec::new();
        msg.write_to(&mut buffer).unwrap();

        assert_eq!(buffer.len(), CELL_SIZE);

        let mut cursor = Cursor::new(buffer);
        let msg2 = Message::read_from(&mut cursor).unwrap();

        assert_eq!(msg.circuit_id, msg2.circuit_id);
        assert_eq!(msg.stream_id, msg2.stream_id);
        assert_eq!(msg.command, msg2.command);
        assert_eq!(msg.data, msg2.data);
    }

    #[test]
    fn test_incomplete_cell() {
        let bytes = vec![0u8; 100]; // Too short for a cell
        assert!(Message::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_message_size_always_cell_size() {
        let msg = Message::new(1, 2, MessageCommand::Data, vec![0; 100]);
        assert_eq!(msg.size(), CELL_SIZE);
    }

    #[test]
    fn test_empty_data_roundtrip() {
        let msg = Message::destroy(42);
        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);

        let msg2 = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg2.circuit_id, 42);
        assert_eq!(msg2.command, MessageCommand::Destroy);
        assert!(msg2.data.is_empty());
    }

    #[test]
    fn test_max_payload_roundtrip() {
        let data = vec![0xAB; MAX_PAYLOAD_SIZE];
        let msg = Message::data(1, 1, data.clone());
        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);

        let msg2 = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg2.data, data);
    }

    #[test]
    fn test_data_ending_in_zero_preserved() {
        // X25519 public keys can end in 0x00 — the payload_len prefix must preserve them
        let mut data = vec![0x42; 32];
        data[31] = 0x00;
        data[30] = 0x00;

        let msg = Message::create(1, data.clone());
        let bytes = msg.to_bytes();
        let msg2 = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg2.data.len(), 32);
        assert_eq!(msg2.data, data);
    }

    #[test]
    fn test_payload_len_field_accuracy() {
        // Verify the payload_len field in the cell matches actual data length
        let data = vec![0xFF; 100];
        let msg = Message::data(5, 10, data);
        let bytes = msg.to_bytes();

        let payload_len = u16::from_be_bytes([bytes[11], bytes[12]]);
        assert_eq!(payload_len, 100);
    }

    #[test]
    fn test_invalid_length_field() {
        let mut cell = vec![0u8; CELL_SIZE];
        // Set length to something other than 510
        cell[0..4].copy_from_slice(&100u32.to_be_bytes());
        cell[10] = MessageCommand::Data.to_u8();

        let result = Message::from_bytes(&cell);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid cell length field"));
    }

    #[test]
    fn test_payload_len_exceeds_max() {
        let mut cell = vec![0u8; CELL_SIZE];
        // Valid length field
        cell[0..4].copy_from_slice(&510u32.to_be_bytes());
        cell[10] = MessageCommand::Data.to_u8();
        // Set payload_len to MAX_PAYLOAD_SIZE + 1 (exceeds limit)
        cell[11..13].copy_from_slice(&((MAX_PAYLOAD_SIZE + 1) as u16).to_be_bytes());

        let result = Message::from_bytes(&cell);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_write_to_stream_rejects_oversized_payload() {
        let data = vec![0xAB; MAX_PAYLOAD_SIZE + 1];
        let msg = Message::data(1, 1, data);

        let mut buf = Vec::new();
        let result = msg.write_to_stream(&mut buf).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let expected_size = MAX_PAYLOAD_SIZE + 1;
        assert!(
            matches!(
                err,
                TorError::PayloadTooLarge { size, max }
                    if size == expected_size && max == MAX_PAYLOAD_SIZE
            ),
            "Expected PayloadTooLarge {{ size: {}, max: {} }}, got: {:?}",
            expected_size,
            MAX_PAYLOAD_SIZE,
            err
        );
    }

    #[tokio::test]
    async fn test_write_to_stream_async_roundtrip() {
        let msg = Message::data(7, 3, b"hello world".to_vec());

        let mut buf = Vec::new();
        msg.write_to_stream(&mut buf).await.unwrap();
        assert_eq!(buf.len(), CELL_SIZE);

        let mut cursor = tokio::io::BufReader::new(buf.as_slice());
        let msg2 = Message::from_stream(&mut cursor).await.unwrap().unwrap();

        assert_eq!(msg.circuit_id, msg2.circuit_id);
        assert_eq!(msg.stream_id, msg2.stream_id);
        assert_eq!(msg.command, msg2.command);
        assert_eq!(msg.data, msg2.data);
    }
}
