//! Message bytes that cost a pointer to clone, and the on-disk store that keeps
//! Proxy history out of RAM (N-06).
//!
//! A [`Body`] is either inline (`Arc<[u8]>`) or a range of a memory-mapped
//! segment file. Proxy history moves every body it keeps into the store
//! ([`spill`]), so an unbounded history costs file-backed pages the kernel can
//! drop and reread, not anonymous memory; and the many places that copy
//! history (site map, reports, scans, project save) copy handles, not bytes.
//!
//! Segments are append-only files under the cache directory, mapped and then
//! unlinked at once: the mapping keeps them alive for the process, and nothing
//! is left on disk after it exits, even after a crash. The project file
//! remains the only durable copy (it is written from these handles).
//! Measured before this change (debug build): 20k items with 4 KB bodies held
//! 95 MB, and a save took 4.3 s on the UI thread.

use crate::sync::Mutex;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Bytes of one message. Derefs to `[u8]`.
#[derive(Clone)]
pub struct Body(Repr);

#[derive(Clone)]
enum Repr {
    Inline(Arc<[u8]>),
    Stored {
        seg: Arc<Segment>,
        off: usize,
        len: usize,
    },
}

impl Body {
    /// True when the bytes live in the on-disk store.
    pub fn is_stored(&self) -> bool {
        matches!(self.0, Repr::Stored { .. })
    }
}

impl Deref for Body {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline(a) => a,
            // SAFETY: [off, off + len) was written before this Body was
            // created and is never written again (segments are append-only);
            // the Arc keeps the mapping alive.
            Repr::Stored { seg, off, len } => unsafe {
                std::slice::from_raw_parts(seg.map.as_ptr().add(*off), *len)
            },
        }
    }
}

impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Default for Body {
    fn default() -> Self {
        Body(Repr::Inline(Arc::from(&[][..])))
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Body({} bytes{})",
            self.len(),
            if self.is_stored() { ", stored" } else { "" }
        )
    }
}

impl PartialEq for Body {
    fn eq(&self, other: &Body) -> bool {
        **self == **other
    }
}
impl Eq for Body {}
impl PartialEq<[u8]> for Body {
    fn eq(&self, other: &[u8]) -> bool {
        **self == *other
    }
}
impl PartialEq<Vec<u8>> for Body {
    fn eq(&self, other: &Vec<u8>) -> bool {
        **self == other[..]
    }
}
impl PartialEq<Body> for Vec<u8> {
    fn eq(&self, other: &Body) -> bool {
        self[..] == **other
    }
}
impl PartialEq<Body> for [u8] {
    fn eq(&self, other: &Body) -> bool {
        *self == **other
    }
}
impl PartialEq<str> for Body {
    fn eq(&self, other: &str) -> bool {
        **self == *other.as_bytes()
    }
}
impl PartialEq<&str> for Body {
    fn eq(&self, other: &&str) -> bool {
        **self == *other.as_bytes()
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body(Repr::Inline(Arc::from(v)))
    }
}
impl From<&[u8]> for Body {
    fn from(v: &[u8]) -> Self {
        Body(Repr::Inline(Arc::from(v)))
    }
}
impl<const N: usize> From<&[u8; N]> for Body {
    fn from(v: &[u8; N]) -> Self {
        Body(Repr::Inline(Arc::from(&v[..])))
    }
}
impl From<String> for Body {
    fn from(v: String) -> Self {
        v.into_bytes().into()
    }
}
impl From<&str> for Body {
    fn from(v: &str) -> Self {
        v.as_bytes().into()
    }
}
impl From<&Body> for Body {
    fn from(v: &Body) -> Self {
        v.clone()
    }
}

/// One mapped segment file (already unlinked). Bytes are written with
/// `pwrite` through `file`, so a full disk is an error; writing through the
/// mapping into a sparse file would raise SIGBUS instead. Reads use the map.
struct Segment {
    map: memmap2::MmapRaw,
    #[cfg(unix)]
    file: std::fs::File,
}

/// Bodies smaller than this stay inline: a handle costs about as much.
const MIN_SPILL: usize = 256;
/// Segment size; a larger body gets a segment of its own size.
const SEGMENT: usize = 64 << 20;

struct Store {
    dir: Option<PathBuf>,
    current: Option<(Arc<Segment>, usize, usize)>,
    next: u64,
    /// After a failure, bodies stay inline until this time; then the store
    /// is tried again (a full disk may have been cleared).
    retry_at: Option<std::time::Instant>,
}

fn store() -> &'static Mutex<Store> {
    static S: OnceLock<Mutex<Store>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Store {
            dir: store_dir(),
            current: None,
            next: 0,
            retry_at: None,
        })
    })
}

/// `WEBPROBE_BODY_DIR`, else `$XDG_CACHE_HOME/webprobe`, else
/// `~/.cache/webprobe`. Not the temp dir: `/tmp` is often tmpfs, which is RAM.
fn store_dir() -> Option<PathBuf> {
    if !cfg!(unix) {
        return None;
    }
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    env("WEBPROBE_BODY_DIR")
        .or_else(|| env("XDG_CACHE_HOME").map(|d| d.join("webprobe")))
        .or_else(|| env("HOME").map(|d| d.join(".cache").join("webprobe")))
}

impl Store {
    fn segment(&mut self, need: usize) -> std::io::Result<(Arc<Segment>, usize)> {
        if let Some((seg, used, cap)) = &self.current {
            if cap - used >= need {
                return Ok((seg.clone(), *used));
            }
        }
        let dir = self
            .dir
            .clone()
            .ok_or_else(|| std::io::Error::other("no body store directory"))?;
        std::fs::create_dir_all(&dir)?;
        let cap = need.max(SEGMENT);
        let path = dir.join(format!("bodies-{}-{}", std::process::id(), self.next));
        self.next += 1;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create_new(true);
        // Private to this user from the first moment: traffic is sensitive.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let file = opts.open(&path)?;
        let mapped = file.set_len(cap as u64).and_then(|()| {
            memmap2::MmapOptions::new()
                .len(cap)
                .map_raw_read_only(&file)
        });
        // Unlinked at once: the mapping and the handle keep the data for this
        // process and nothing outlives it.
        let _ = std::fs::remove_file(&path);
        let seg = Arc::new(Segment {
            map: mapped?,
            #[cfg(unix)]
            file,
        });
        self.current = Some((seg.clone(), 0, cap));
        Ok((seg, 0))
    }
}

/// A private, already-unlinked file in the body store's directory, for
/// bytes whose final size is not known yet (a streaming response being
/// recorded). `None` when there is no store directory.
pub fn scratch_file() -> Option<std::fs::File> {
    let dir = store().lock().unwrap().dir.clone()?;
    std::fs::create_dir_all(&dir).ok()?;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = dir.join(format!(
        "stream-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = opts.open(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    Some(file)
}

impl Body {
    /// The first `len` bytes of `file` (written through it), mapped: the
    /// bytes stay file-backed, not in anonymous memory.
    pub fn from_file(file: std::fs::File, len: usize) -> std::io::Result<Body> {
        if len == 0 {
            return Ok(Body::default());
        }
        let map = memmap2::MmapOptions::new()
            .len(len)
            .map_raw_read_only(&file)?;
        let seg = Arc::new(Segment {
            map,
            #[cfg(unix)]
            file,
        });
        Ok(Body(Repr::Stored { seg, off: 0, len }))
    }
}

/// `body` moved into the on-disk store (a clone when it is small, already
/// stored, or the store is unavailable; the first failure is logged and
/// later bodies stay inline).
pub fn spill(body: &Body) -> Body {
    if body.is_stored() || body.len() < MIN_SPILL {
        return body.clone();
    }
    let mut st = store().lock().unwrap();
    if st.retry_at.is_some_and(|t| std::time::Instant::now() < t) {
        return body.clone();
    }
    match st
        .segment(body.len())
        .and_then(|(seg, off)| write_at(&seg, off, body).map(|()| (seg, off)))
    {
        Ok((seg, off)) => {
            st.retry_at = None;
            if let Some((_, used, _)) = &mut st.current {
                *used = off + body.len();
            }
            Body(Repr::Stored {
                seg,
                off,
                len: body.len(),
            })
        }
        Err(e) => {
            if st.retry_at.is_none() {
                eprintln!(
                    "webprobe: history bodies stay in memory for now, the body store failed: {e}"
                );
            }
            // Start a fresh segment next time and back off for a minute.
            st.current = None;
            st.retry_at = Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
            body.clone()
        }
    }
}

/// Write `body` at `off` of the segment with `pwrite`: [off, off + len) is
/// past every range handed out and inside the file; no reader can see it
/// until the Body is returned.
#[cfg(unix)]
fn write_at(seg: &Segment, off: usize, body: &[u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(&seg.file, body, off as u64)
}

#[cfg(not(unix))]
fn write_at(_seg: &Segment, _off: usize, _body: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::other("no body store on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spilled_bodies_read_back_exactly_and_small_ones_stay_inline() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let b = spill(&Body::from(big.clone()));
        if cfg!(unix) && store_dir().is_some() {
            assert!(b.is_stored());
        }
        assert_eq!(b, big);
        let again = spill(&b);
        assert_eq!(again, big, "spilling a stored body is a clone");
        let small = spill(&Body::from("GET / HTTP/1.1\r\n\r\n"));
        assert!(!small.is_stored());
        assert_eq!(small, "GET / HTTP/1.1\r\n\r\n");
        // A body larger than a segment gets a segment of its own.
        let huge = vec![7u8; SEGMENT + 1];
        assert_eq!(&spill(&Body::from(huge.clone()))[..], &huge[..]);
        assert_eq!(
            &b[..],
            &big[..],
            "earlier bodies are unaffected by new segments"
        );
    }

    #[test]
    fn concurrent_spills_do_not_overlap() {
        let handles: Vec<_> = (0..8u8)
            .map(|t| {
                std::thread::spawn(move || {
                    (0..200)
                        .map(|i| (t, i, spill(&Body::from(vec![t ^ (i as u8); 300 + i]))))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for h in handles {
            for (t, i, b) in h.join().unwrap() {
                assert_eq!(b.len(), 300 + i);
                assert!(b.iter().all(|&x| x == t ^ (i as u8)));
            }
        }
    }
}
