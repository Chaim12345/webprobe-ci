// Regression tests for read_request's head scan.
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
    let raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";
    for step in 1..=5 {
        let got = read_request(&mut Trickle(raw, step)).unwrap();
        assert_eq!(got, raw.to_vec(), "step {step}");
    }
    let lf = b"GET / HTTP/1.1\nHost: h\n\n";
    for step in 1..=4 {
        assert_eq!(
            read_request(&mut Trickle(lf, step)).unwrap(),
            lf.to_vec(),
            "lf step {step}"
        );
    }
}

#[test]
fn a_header_flood_is_rejected_in_linear_time() {
    // Rescanning the whole buffer on every 8 KiB read made this take ~40 s
    // in a debug build; a linear scan finishes in well under a second.
    let flood = vec![b'a'; 5 * 1024 * 1024];
    let start = Instant::now();
    let err = read_request(&mut Cursor::new(flood)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "took {:?}",
        start.elapsed()
    );
}
