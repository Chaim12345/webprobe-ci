// Sequencer bit-level analysis.
//
// Burp's Sequencer judges a token by its bits: every bit position of the
// token is treated as a sequence across the samples and put through
// randomness tests; the positions that pass at a significance level are the
// token's "effective entropy" at that level, and the figure at 1% gives the
// overall rating (thresholds from build 52685, burp.Zr8b.ZF: under 16 bits
// "extremely poor", 24 "very poor", 32 "poor", 40 "reasonable", 60 "good",
// 80 "very good", otherwise "excellent").
//
// Implemented here are the four FIPS 140-2 style tests (monobit, poker, runs,
// long runs) as p-values. Burp additionally runs spectral, correlation and
// compression tests, which are not implemented.

use serde::Serialize;

use crate::analysis::regularized_gamma_q;

/// Burp will not analyse fewer tokens than this.
pub const MIN_SAMPLES: usize = 100;

/// Significance levels Burp reports effective entropy at.
pub const LEVELS: [f64; 5] = [0.00001, 0.0001, 0.001, 0.01, 0.1];
pub const LEVEL_LABELS: [&str; 5] = [">0.001%", ">0.01%", ">0.1%", ">1%", ">10%"];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BitResult {
    /// Bit position in the token, 0 = most significant bit of the first
    /// character that varies.
    pub position: usize,
    pub monobit: f64,
    /// `None` below 320 samples (fewer than 80 four-bit blocks).
    pub poker: Option<f64>,
    pub runs: f64,
    pub long_runs: f64,
    /// The smallest of the test p-values: the position passes a level when
    /// this is at or above it.
    pub combined: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BitReport {
    pub samples: usize,
    /// Bits analysed per token: over the length all tokens share, the sum of
    /// the bits each character position needs for its character set.
    pub token_bits: usize,
    pub bits: Vec<BitResult>,
    /// Passing bit positions at each of [`LEVELS`].
    pub effective_entropy: [usize; 5],
    pub rating: &'static str,
}

/// erfc(x) for x >= 0, through the regularised incomplete gamma function.
fn erfc(x: f64) -> f64 {
    if x <= 0.0 {
        1.0
    } else {
        regularized_gamma_q(0.5, x * x)
    }
}

/// Burp's wording for an amount of effective entropy at the 1% level.
pub fn rating(effective_bits: usize) -> &'static str {
    match effective_bits {
        0..=15 => "extremely poor",
        16..=23 => "very poor",
        24..=31 => "poor",
        32..=39 => "reasonable",
        40..=59 => "good",
        60..=79 => "very good",
        _ => "excellent",
    }
}

/// One sequence per bit position, over the length all samples share.
///
/// As in Burp, each character position is converted to bits according to the
/// size of the character set seen at that position: a hex digit carries four
/// bits, a base64 character six, and a position that never changes none. The
/// character's index in the position's sorted alphabet is what is tested, so
/// a token's encoding does not hide (or invent) entropy the way raw ASCII
/// bits would.
pub fn bit_columns(samples: &[Vec<u8>]) -> Vec<Vec<bool>> {
    let len = samples.iter().map(Vec::len).min().unwrap_or(0);
    let mut columns = Vec::new();
    for pos in 0..len {
        let mut index_of = [0u16; 256];
        let mut seen = [false; 256];
        for s in samples {
            seen[s[pos] as usize] = true;
        }
        let mut size = 0u16;
        for (byte, present) in seen.iter().enumerate() {
            if *present {
                index_of[byte] = size;
                size += 1;
            }
        }
        if size < 2 {
            continue;
        }
        // Bits needed for the largest index, most significant first.
        let width = 16 - (size - 1).leading_zeros();
        for bit in (0..width).rev() {
            columns.push(
                samples
                    .iter()
                    .map(|s| index_of[s[pos] as usize] >> bit & 1 == 1)
                    .collect(),
            );
        }
    }
    columns
}

/// Proportion-of-ones test.
pub fn monobit(bits: &[bool]) -> f64 {
    let n = bits.len() as f64;
    let ones = bits.iter().filter(|b| **b).count() as f64;
    erfc((2.0 * ones - n).abs() / n.sqrt() / std::f64::consts::SQRT_2)
}

/// Number-of-runs test (too many or too few alternations).
pub fn runs(bits: &[bool]) -> f64 {
    let n = bits.len() as f64;
    let pi = bits.iter().filter(|b| **b).count() as f64 / n;
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() {
        return 0.0;
    }
    let v = 1.0 + bits.windows(2).filter(|w| w[0] != w[1]).count() as f64;
    erfc((v - 2.0 * n * pi * (1.0 - pi)).abs() / (2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi)))
}

/// Poker test: the sixteen four-bit patterns should be equally common.
pub fn poker(bits: &[bool]) -> Option<f64> {
    let k = bits.len() / 4;
    if k < 80 {
        return None;
    }
    let mut counts = [0f64; 16];
    for block in bits.as_chunks::<4>().0 {
        let v = block
            .iter()
            .fold(0usize, |acc, b| acc << 1 | usize::from(*b));
        counts[v] += 1.0;
    }
    let k = k as f64;
    let x = 16.0 / k * counts.iter().map(|c| c * c).sum::<f64>() - k;
    Some(regularized_gamma_q(7.5, x.max(0.0) / 2.0))
}

/// Longest run of equal bits: the chance of one at least this long in a
/// random sequence (first-order approximation 1 - exp(-n / 2^r)).
pub fn long_runs(bits: &[bool]) -> f64 {
    let mut longest = 0usize;
    let mut current = 0usize;
    let mut last = None;
    for b in bits {
        current = if last == Some(*b) { current + 1 } else { 1 };
        last = Some(*b);
        longest = longest.max(current);
    }
    1.0 - (-(bits.len() as f64) / 2f64.powi(longest as i32)).exp()
}

/// The bit-level report for these token samples, or `None` with fewer than
/// [`MIN_SAMPLES`] of them or when the shortest token is empty.
pub fn analyze(samples: &[Vec<u8>]) -> Option<BitReport> {
    if samples.len() < MIN_SAMPLES || samples.iter().any(Vec::is_empty) {
        return None;
    }
    let columns = bit_columns(samples);
    // No variable positions is a valid result: the observed tokens are
    // constant and have zero effective bits, not insufficient samples.
    let bits: Vec<BitResult> = columns
        .iter()
        .enumerate()
        .map(|(position, col)| {
            let (m, p, r, l) = (monobit(col), poker(col), runs(col), long_runs(col));
            let combined = [Some(m), p, Some(r), Some(l)]
                .into_iter()
                .flatten()
                .fold(1.0f64, f64::min);
            BitResult {
                position,
                monobit: m,
                poker: p,
                runs: r,
                long_runs: l,
                combined,
            }
        })
        .collect();
    let mut effective_entropy = [0usize; 5];
    for (i, level) in LEVELS.iter().enumerate() {
        effective_entropy[i] = bits.iter().filter(|b| b.combined >= *level).count();
    }
    Some(BitReport {
        samples: samples.len(),
        token_bits: columns.len(),
        rating: rating(effective_entropy[3]),
        bits,
        effective_entropy,
    })
}

/// Summary of the implemented tests, not a claim of cryptographic security.
pub fn summary(report: &BitReport) -> String {
    format!(
        "The overall quality of randomness within the sample is estimated to be: {}. At a significance level of 1%, the amount of effective entropy is estimated to be: {} bits. This is a test-pass estimate from monobit, poker (320+ samples), runs and approximate long-run tests. Spectral, correlation and compression tests are not implemented; passing does not prove unpredictability. Only the common token prefix is analyzed.",
        report.rating, report.effective_entropy[3]
    )
}

/// The per-bit results as CSV (one row per bit position).
pub fn report_csv(report: &BitReport) -> String {
    let mut out = String::from("Bit,Monobit,Poker,Runs,Long runs,Combined\r\n");
    for b in &report.bits {
        let poker = b.poker.map(|p| format!("{p:.6}")).unwrap_or_default();
        out.push_str(&format!(
            "{},{:.6},{},{:.6},{:.6},{:.6}\r\n",
            b.position, b.monobit, poker, b.runs, b.long_runs, b.combined
        ));
    }
    out
}

/// The report as JSON (summary figures and every bit position).
pub fn report_json(report: &BitReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_default()
}

/// The token samples one per line, as Burp's "Save tokens" writes them.
pub fn tokens_text(samples: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in samples {
        out.extend_from_slice(s);
        out.push(b'\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 64-bit generator (splitmix64), so tests need no clock.
    fn random_tokens(count: usize, len: usize, mut seed: u64) -> Vec<Vec<u8>> {
        let mut next = move || {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        (0..count)
            .map(|_| (0..len).map(|_| (next() >> 24) as u8).collect())
            .collect()
    }

    #[test]
    fn constant_manual_load_fixture_has_zero_effective_bits_at_every_level() {
        // PR #112: the real Burp fixture contains 1,024 identical lines.
        let text = "ABCD0123456789abcdef\n".repeat(1024);
        let samples: Vec<Vec<u8>> = text.lines().map(|line| line.as_bytes().to_vec()).collect();
        let report = analyze(&samples).expect("constant non-empty tokens must be analyzed");
        assert_eq!(report.samples, 1024);
        assert_eq!(report.token_bits, 0);
        assert!(report.bits.is_empty());
        assert_eq!(report.effective_entropy, [0; 5]);
        assert_eq!(report.rating, "extremely poor");
        assert!(summary(&report)
            .contains("1%, the amount of effective entropy is estimated to be: 0 bits."));
        println!(
            "constant manual load: {} samples, {:?} effective bits, {}",
            report.samples, report.effective_entropy, report.rating
        );
        let json: serde_json::Value = serde_json::from_str(&report_json(&report)).unwrap();
        assert_eq!(
            json["effective_entropy"],
            serde_json::json!([0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn constant_tokens_at_minimum_sample_boundary_are_valid() {
        assert!(analyze(&vec![b"fixed".to_vec(); MIN_SAMPLES - 1]).is_none());
        let report = analyze(&vec![b"fixed".to_vec(); MIN_SAMPLES]).unwrap();
        assert_eq!(report.effective_entropy, [0; 5]);
        assert!(analyze(&vec![Vec::new(); MIN_SAMPLES]).is_none());
    }

    #[test]
    fn replacing_batch_with_same_count_recomputes_zero_entropy() {
        let samples = random_tokens(1024, 16, 42);
        let random = analyze(&samples).unwrap();
        assert!(random.effective_entropy[3] > 80);
        let constant = analyze(&vec![b"ABCD0123456789abcdef".to_vec(); samples.len()]).unwrap();
        assert_eq!(random.samples, constant.samples);
        assert_eq!(constant.effective_entropy, [0; 5]);
        assert_ne!(random, constant);
    }

    #[test]
    fn rating_uses_burps_thresholds() {
        let at = |n| rating(n);
        assert_eq!(
            [at(0), at(15), at(16), at(23), at(24), at(31)],
            [
                "extremely poor",
                "extremely poor",
                "very poor",
                "very poor",
                "poor",
                "poor"
            ]
        );
        assert_eq!(
            [
                at(32),
                at(39),
                at(40),
                at(59),
                at(60),
                at(79),
                at(80),
                at(512)
            ],
            [
                "reasonable",
                "reasonable",
                "good",
                "good",
                "very good",
                "very good",
                "excellent",
                "excellent"
            ]
        );
    }

    #[test]
    fn single_tests_reject_the_patterns_they_are_for() {
        let constant = vec![true; 2000];
        assert!(monobit(&constant) < 1e-9);
        assert!(long_runs(&constant) < 1e-9);
        // Perfect alternation is balanced but has far too many runs.
        let alternating: Vec<bool> = (0..2000).map(|i| i % 2 == 0).collect();
        assert!(monobit(&alternating) > 0.99);
        assert!(runs(&alternating) < 1e-9);
        // 0011 repeated: balanced, run count as expected, but only two of the
        // sixteen four-bit patterns ever occur... here just one.
        let blocks: Vec<bool> = (0..2000).map(|i| i % 4 >= 2).collect();
        assert!(poker(&blocks).unwrap() < 1e-9);
        // Too few samples for the poker test.
        assert_eq!(poker(&[true; 300]), None);
    }

    #[test]
    fn random_tokens_rate_excellent_and_fixed_parts_do_not_count() {
        let random = random_tokens(4000, 16, 7);
        let r = analyze(&random).unwrap();
        assert_eq!((r.samples, r.token_bits, r.bits.len()), (4000, 128, 128));
        assert!(r.effective_entropy[3] >= 110, "{:?}", r.effective_entropy);
        assert_eq!(r.rating, "excellent");
        // Stricter levels pass at least as many bits as looser ones.
        assert!(
            r.effective_entropy.windows(2).all(|w| w[0] >= w[1]),
            "{:?}",
            r.effective_entropy
        );
        assert!(summary(&r).starts_with(
            "The overall quality of randomness within the sample is estimated to be: excellent."
        ));

        // An 8-byte constant prefix contributes no bits at all: 64 remain.
        let half: Vec<Vec<u8>> = random
            .iter()
            .map(|t| [b"SESSION-".as_slice(), &t[..8]].concat())
            .collect();
        let h = analyze(&half).unwrap();
        assert_eq!(h.token_bits, 64);
        assert!(
            (52..=64).contains(&h.effective_entropy[3]),
            "{:?}",
            h.effective_entropy
        );
        assert!(matches!(h.rating, "good" | "very good"));

        // The same 8 random bytes written as 16 hex digits are still 64 bits:
        // four per digit, not eight bits of ASCII.
        let hex: Vec<Vec<u8>> = random
            .iter()
            .map(|t| {
                t[..8]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .into_bytes()
            })
            .collect();
        let x = analyze(&hex).unwrap();
        assert_eq!(x.token_bits, 64);
        assert!(
            (52..=64).contains(&x.effective_entropy[3]),
            "{:?}",
            x.effective_entropy
        );
    }

    #[test]
    fn counters_rate_extremely_poor_and_small_samples_are_refused() {
        let counter: Vec<Vec<u8>> = (0..3000u32)
            .map(|i| format!("{i:08}").into_bytes())
            .collect();
        let c = analyze(&counter).unwrap();
        assert!(c.effective_entropy[3] < 16, "{:?}", c.effective_entropy);
        assert_eq!(c.rating, "extremely poor");
        assert_eq!(analyze(&random_tokens(99, 16, 1)), None);
        assert_eq!(analyze(&vec![Vec::new(); 200]), None);
    }

    #[test]
    fn exports_list_every_bit_and_tokens_round_trip() {
        // Hex digits: every one of the 16 symbols turns up, so 4 bits each.
        let tokens: Vec<Vec<u8>> = random_tokens(400, 2, 3)
            .iter()
            .map(|t| format!("{:02x}{:02x}", t[0], t[1]).into_bytes())
            .collect();
        let r = analyze(&tokens).unwrap();
        let csv = report_csv(&r);
        assert!(csv.starts_with("Bit,Monobit,Poker,Runs,Long runs,Combined\r\n"));
        assert_eq!(csv.lines().count(), 1 + 16);
        let json: serde_json::Value = serde_json::from_str(&report_json(&r)).unwrap();
        assert_eq!(json["samples"], 400);
        assert_eq!(json["bits"].as_array().unwrap().len(), 16);
        assert_eq!(json["rating"], r.rating);
        let text = tokens_text(&[b"abc".to_vec(), b"de".to_vec()]);
        assert_eq!(text, b"abc\nde\n");
    }
}
