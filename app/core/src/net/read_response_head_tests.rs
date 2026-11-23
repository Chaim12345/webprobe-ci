// Regression tests for read_response_head's head scan.
use super::*;
use std::io::Cursor;

/// A reader that yields at most `n` bytes per call, like a slow socket.
struct Trickle<'a>(&'a [u8], usize);
impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.1.min(self.0.len()).min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

#[test]
fn head_terminator_split_across_reads_is_found() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for step in 1..=5 {
        let got = read_response_head(&mut Trickle(raw, step)).unwrap();
        assert_eq!(got, raw.to_vec(), "step {step}");
    }
    let lf = b"HTTP/1.1 200 OK\nContent-Length: 0\n\n";
    for step in 1..=4 {
        assert_eq!(
            read_response_head(&mut Trickle(lf, step)).unwrap(),
            lf.to_vec(),
            "lf step {step}"
        );
    }
}

#[test]
fn stops_at_the_boundary_without_reading_ahead() {
    // The head is followed by a WebSocket frame: read_response_head must
    // leave those bytes on the stream for the frame parser.
    let mut bytes = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
    bytes.extend_from_slice(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let mut cur = Cursor::new(bytes);
    let head = read_response_head(&mut cur).unwrap();
    assert_eq!(head, b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec());
    assert_eq!(cur.position() as usize, head.len());
}

#[test]
fn a_large_response_head_is_scanned_in_linear_time() {
    // Rescanning the whole buffer on every 1-byte read made a 64 KiB head
    // take ~30 s in a debug build; scanning only the tail is far under that.
    let mut raw = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
    raw.extend_from_slice(&vec![b'a'; 60 * 1024]);
    raw.extend_from_slice(b"\r\n\r\n");
    let start = Instant::now();
    let got = read_response_head(&mut Cursor::new(raw.clone())).unwrap();
    assert_eq!(got, raw);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn a_head_past_the_size_cap_still_stops() {
    // No terminator anywhere: the 64 KiB cap ends the loop, and that scan
    // must be linear too.
    let raw = vec![b'a'; 80 * 1024];
    let start = Instant::now();
    let got = read_response_head(&mut Cursor::new(raw)).unwrap();
    assert_eq!(got.len(), 64 * 1024 + 1);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "took {:?}",
        start.elapsed()
    );
}
