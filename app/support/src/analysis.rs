//! Deterministic analysis helpers shared by the Sequencer, Comparer and Search
//! tools: byte-entropy statistics, line/word diffs and cross-tool search.
//!
//! Everything in this module is pure: identical inputs always produce
//! identical output, and empty inputs are handled without panicking.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

// ---------- Token statistics ----------

/// Aggregate statistics for a set of token samples.
///
/// `token_length` is the mean sample length in bytes, rounded down. Entropy is
/// always computed over the concatenated bytes, so `total_entropy_bits` is
/// `bits_per_character * total byte count`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenStats {
    pub sample_count: usize,
    pub token_length: usize,
    pub bits_per_character: f64,
    pub total_entropy_bits: f64,
    /// Byte counts in ascending byte order. Bytes with a zero count are
    /// omitted, making the distribution deterministic and JSON-friendly.
    pub char_distribution: Vec<(char, usize)>,
}

pub fn analyze_tokens(samples: &[Vec<u8>]) -> TokenStats {
    let mut counts = [0usize; 256];
    let mut total_bytes = 0usize;

    for sample in samples {
        total_bytes = total_bytes.saturating_add(sample.len());
        for &byte in sample {
            counts[byte as usize] = counts[byte as usize].saturating_add(1);
        }
    }

    let bits_per_character = if total_bytes == 0 {
        0.0
    } else {
        let total = total_bytes as f64;
        counts
            .iter()
            .copied()
            .filter(|&count| count > 0)
            .map(|count| {
                let probability = count as f64 / total;
                -probability * probability.log2()
            })
            .sum::<f64>()
    };

    let mut char_distribution = Vec::new();
    for (byte, &count) in counts.iter().enumerate() {
        if count > 0 {
            char_distribution.push((char::from(byte as u8), count));
        }
    }

    TokenStats {
        sample_count: samples.len(),
        token_length: if samples.is_empty() {
            0
        } else {
            total_bytes / samples.len()
        },
        bits_per_character,
        total_entropy_bits: bits_per_character * total_bytes as f64,
        char_distribution,
    }
}

// ---------- Line and word diffs ----------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    #[default]
    Same,
    Added,
    Removed,
    Changed,
}

// ---------- Cross-tool search ----------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchRecord {
    pub id: String,
    pub tool: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub record_id: String,
    pub tool: String,
    pub title: String,
    pub excerpt: String,
}

const EXCERPT_BEFORE: usize = 60;
const EXCERPT_AFTER: usize = 100;

/// Find records whose body, title or tool contains `query`.
///
/// Results follow the input order. The excerpt comes from the first matching
/// field in body/title/tool order and is deterministic: at most 60 characters
/// before and 100 after the match, whitespace collapsed, with ellipses where
/// the text was cut.
pub fn search_records(
    case_sensitive: bool,
    query: &str,
    records: &[SearchRecord],
) -> Vec<SearchHit> {
    if query.is_empty() {
        return Vec::new();
    }

    let folded_query = if case_sensitive {
        String::new()
    } else {
        query.to_lowercase()
    };

    let mut hits = Vec::new();
    for record in records {
        let excerpt = find_excerpt(&record.body, query, &folded_query, case_sensitive)
            .or_else(|| find_excerpt(&record.title, query, &folded_query, case_sensitive))
            .or_else(|| find_excerpt(&record.tool, query, &folded_query, case_sensitive));

        if let Some(excerpt) = excerpt {
            hits.push(SearchHit {
                record_id: record.id.clone(),
                tool: record.tool.clone(),
                title: record.title.clone(),
                excerpt,
            });
        }
    }
    hits
}

/// Lowercased `text` plus, for every folded character, the index of the
/// original character it came from.
fn lowercased_with_map(text: &str) -> (String, Vec<usize>) {
    let mut folded = String::with_capacity(text.len());
    let mut folded_to_original = Vec::new();
    for (char_index, character) in text.chars().enumerate() {
        for folded_character in character.to_lowercase() {
            folded.push(folded_character);
            folded_to_original.push(char_index);
        }
    }
    (folded, folded_to_original)
}

fn find_excerpt(
    text: &str,
    query: &str,
    folded_query: &str,
    case_sensitive: bool,
) -> Option<String> {
    if query.is_empty() {
        return None;
    }

    let (match_character, query_characters) = if case_sensitive {
        let byte_index = text.find(query)?;
        (text[..byte_index].chars().count(), query.chars().count())
    } else {
        // Lowercasing can expand a character (e.g. 'İ' becomes two chars), so
        // the folded match position has to be mapped back onto the original
        // string before slicing the excerpt.
        let (folded_text, folded_to_original) = lowercased_with_map(text);
        let byte_index = folded_text.find(folded_query)?;
        let folded_start = folded_text[..byte_index].chars().count();
        let folded_end = folded_start + folded_query.chars().count();
        let original_start = folded_to_original[folded_start];
        let original_end = folded_to_original
            .get(folded_end)
            .copied()
            .unwrap_or_else(|| text.chars().count());
        (original_start, original_end.saturating_sub(original_start))
    };

    Some(make_excerpt(text, match_character, query_characters.max(1)))
}

fn make_excerpt(text: &str, match_character: usize, query_characters: usize) -> String {
    let characters: Vec<char> = text.chars().collect();
    let total = characters.len();
    if total == 0 {
        return String::new();
    }

    let match_character = match_character.min(total);
    let start = match_character.saturating_sub(EXCERPT_BEFORE);
    let match_end = match_character.saturating_add(query_characters).min(total);
    let end = match_end.saturating_add(EXCERPT_AFTER).min(total);

    let mut excerpt = String::new();
    if start > 0 {
        excerpt.push('…');
    }
    for &character in &characters[start..end] {
        excerpt.push(if character.is_whitespace() {
            ' '
        } else {
            character
        });
    }
    if end < total {
        excerpt.push('…');
    }

    let collapsed = excerpt.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        "…".to_string()
    } else {
        collapsed
    }
}

// ---------- Sequencer workspace ----------
//
// Canonical Sequencer token analysis in the reference tree (build 51467,
// burp.Zrdz) offers Count, Transitions and bit-level FIPS/spectral tests. This
// workspace implements the requested descriptive subset: token counts,
// numeric-token statistics, character entropy and a chi-square test against a
// uniform distribution over the observed character alphabet. It does not claim
// FIPS compliance.
//
// These items are additive; the existing TokenStats API above stays untouched.

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NumericStats {
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    /// Population standard deviation; the denominator is `count`.
    pub std_dev: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ChiSquareStats {
    pub statistic: f64,
    pub degrees_of_freedom: usize,
    /// Upper-tail probability, from the chi-square survival function.
    pub p_value: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SequencerReport {
    pub token_count: usize,
    pub unique_tokens: usize,
    pub numeric: Option<NumericStats>,
    pub total_characters: usize,
    pub entropy_bits_per_character: f64,
    pub effective_alphabet: f64,
    pub chi_square: Option<ChiSquareStats>,
    /// Character counts in ascending Unicode scalar order.
    pub character_distribution: Vec<(char, usize)>,
}

/// Analyse already-extracted tokens. Empty strings are ignored.
pub fn analyze_sequence(tokens: &[String]) -> SequencerReport {
    let used: Vec<&str> = tokens
        .iter()
        .map(String::as_str)
        .filter(|token| !token.is_empty())
        .collect();

    let unique_tokens = used.iter().copied().collect::<HashSet<_>>().len();
    let numeric = numeric_stats(&used);

    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    let mut total_characters = 0usize;
    for token in &used {
        for character in token.chars() {
            *counts.entry(character).or_insert(0) += 1;
            total_characters += 1;
        }
    }

    let entropy_bits_per_character = if total_characters == 0 {
        0.0
    } else {
        let total = total_characters as f64;
        counts
            .values()
            .map(|&count| {
                let probability = count as f64 / total;
                -probability * probability.log2()
            })
            .sum::<f64>()
    };
    let effective_alphabet = if total_characters == 0 {
        0.0
    } else {
        2f64.powf(entropy_bits_per_character)
    };
    let chi_square = chi_square_uniform(&counts, total_characters);

    SequencerReport {
        token_count: used.len(),
        unique_tokens,
        numeric,
        total_characters,
        entropy_bits_per_character,
        effective_alphabet,
        chi_square,
        character_distribution: counts.into_iter().collect(),
    }
}

fn numeric_stats(tokens: &[&str]) -> Option<NumericStats> {
    let mut values = Vec::new();
    for token in tokens {
        if let Ok(value) = token.trim().parse::<f64>() {
            if value.is_finite() {
                values.push(value);
            }
        }
    }
    let count = values.len();
    if count == 0 {
        return None;
    }

    let mean = values.iter().sum::<f64>() / count as f64;
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / count as f64;

    Some(NumericStats {
        count,
        min: values.iter().copied().fold(f64::INFINITY, f64::min),
        max: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        mean,
        std_dev: variance.sqrt(),
    })
}

fn chi_square_uniform(counts: &BTreeMap<char, usize>, total: usize) -> Option<ChiSquareStats> {
    let classes = counts.len();
    if classes < 2 || total == 0 {
        return None;
    }
    let expected = total as f64 / classes as f64;
    if !expected.is_finite() || expected <= 0.0 {
        return None;
    }
    let statistic = counts
        .values()
        .map(|&observed| {
            let delta = observed as f64 - expected;
            delta * delta / expected
        })
        .sum::<f64>();
    let degrees_of_freedom = classes - 1;
    let raw = chi_square_survival(statistic, degrees_of_freedom as f64 / 2.0);

    Some(ChiSquareStats {
        statistic,
        degrees_of_freedom,
        p_value: if raw.is_finite() {
            Some(raw.clamp(0.0, 1.0))
        } else {
            None
        },
    })
}

/// Upper tail of the chi-square distribution: the regularised incomplete
/// gamma function Q(df/2, statistic/2), computed with the standard series /
/// continued-fraction pair.
fn chi_square_survival(statistic: f64, shape: f64) -> f64 {
    let x = statistic / 2.0;
    regularized_gamma_q(shape, x)
}

pub fn regularized_gamma_q(shape: f64, x: f64) -> f64 {
    if !shape.is_finite() || !x.is_finite() || shape <= 0.0 || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }
    if x < shape + 1.0 {
        1.0 - gamma_series(shape, x)
    } else {
        gamma_continued_fraction(shape, x)
    }
}

fn gamma_series(shape: f64, x: f64) -> f64 {
    let mut term = 1.0 / shape;
    let mut sum = term;
    let mut argument = shape;
    for _ in 0..20_000 {
        argument += 1.0;
        term *= x / argument;
        sum += term;
        if term.abs() < sum.abs() * 1e-14 {
            break;
        }
    }
    let log_prefix = shape * x.ln() - x - ln_gamma(shape);
    if log_prefix.is_finite() && sum.is_finite() {
        (log_prefix + sum.ln()).exp()
    } else {
        f64::NAN
    }
}

fn gamma_continued_fraction(shape: f64, x: f64) -> f64 {
    const FPMIN: f64 = 1e-300;
    let mut b = x + 1.0 - shape;
    let mut c = 1.0 / FPMIN;
    let mut d = if b.abs() < FPMIN {
        1.0 / FPMIN
    } else {
        1.0 / b
    };
    let mut h = d;
    for index in 1..20_000u32 {
        let an = -(index as f64) * (index as f64 - shape);
        b += 2.0;
        d = an * d + b;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = b + an / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < 1e-14 {
            break;
        }
    }
    let log_prefix = shape * x.ln() - x - ln_gamma(shape);
    if log_prefix.is_finite() && h.is_finite() {
        (log_prefix + h.ln()).exp()
    } else {
        f64::NAN
    }
}

fn ln_gamma(value: f64) -> f64 {
    const COEFFICIENTS: [f64; 6] = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut y = value;
    let temporary = (value + 0.5) * (value + 5.5).ln() - (value + 5.5);
    let mut series = 1.000_000_000_190_015;
    for coefficient in COEFFICIENTS {
        y += 1.0;
        series += coefficient / y;
    }
    // ln Gamma(x) = (x + 0.5) ln(x + 5.5) - (x + 5.5) + ln(sqrt(2 pi) * series / x).
    // The first two terms were subtracted here until 2026-11-17, which made
    // every chi-square p-value wrong (Q(7.5, 7.5) came out as -1.9 million).
    temporary + (2.506_628_274_631_000_5 * series / value).ln()
}

// ---------- Comparer workspace ----------
//
// The canonical Comparer uses an optimized byte/word diff (technical report on
// build 51467; the Montoya API surfaced with live jar 52685 only exposes
// sendToComparer). This workspace implements the requested line-level LCS with
// row locations and byte lengths. Hirschberg's algorithm keeps the exact
// longest-common-subsequence while using O(min(left, right)) extra memory.

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CompareRow {
    pub kind: DiffKind,
    /// 1-based line number on the left side, when the row exists there.
    pub left_line: Option<usize>,
    /// 1-based line number on the right side, when the row exists there.
    pub right_line: Option<usize>,
    pub text: String,
    pub left_bytes: usize,
    pub right_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ComparerState {
    pub left: String,
    pub right: String,
    pub rows: Vec<CompareRow>,
    pub common: usize,
    pub added: usize,
    pub removed: usize,
    pub common_bytes: usize,
    pub added_bytes: usize,
    pub removed_bytes: usize,
    pub status: String,
}

impl ComparerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Recompute the exact line-level LCS diff and summary counts.
    pub fn recompute(&mut self) {
        self.rows = diff_line_rows(&self.left, &self.right);
        self.common = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Same)
            .count();
        self.added = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Added)
            .count();
        self.removed = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Removed)
            .count();
        self.common_bytes = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Same)
            .map(|row| row.left_bytes)
            .sum();
        self.added_bytes = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Added)
            .map(|row| row.right_bytes)
            .sum();
        self.removed_bytes = self
            .rows
            .iter()
            .filter(|row| row.kind == DiffKind::Removed)
            .map(|row| row.left_bytes)
            .sum();
        self.status = format!(
            "{} common ({} bytes), {} added ({} bytes), {} removed ({} bytes)",
            self.common,
            self.common_bytes,
            self.added,
            self.added_bytes,
            self.removed,
            self.removed_bytes
        );
    }

    pub fn clear(&mut self) {
        self.left.clear();
        self.right.clear();
        self.rows.clear();
        self.status.clear();
        self.common = 0;
        self.added = 0;
        self.removed = 0;
        self.common_bytes = 0;
        self.added_bytes = 0;
        self.removed_bytes = 0;
    }
}

/// Line-level LCS diff. Line text excludes the line terminator, so byte
/// lengths are the displayed bytes only.
pub fn diff_line_rows(left: &str, right: &str) -> Vec<CompareRow> {
    let left_lines: Vec<&str> = left.lines().collect();
    let right_lines: Vec<&str> = right.lines().collect();
    let matches = lcs_hirschberg(&left_lines, &right_lines);

    let mut rows = Vec::with_capacity(left_lines.len() + right_lines.len());
    let mut left_index = 0usize;
    let mut right_index = 0usize;

    for (left_match, right_match) in matches {
        while left_index < left_match {
            rows.push(removed_row(&left_lines, left_index));
            left_index += 1;
        }
        while right_index < right_match {
            rows.push(added_row(&right_lines, right_index));
            right_index += 1;
        }
        rows.push(CompareRow {
            kind: DiffKind::Same,
            left_line: Some(left_match + 1),
            right_line: Some(right_match + 1),
            text: left_lines[left_match].to_string(),
            left_bytes: left_lines[left_match].len(),
            right_bytes: right_lines[right_match].len(),
        });
        left_index = left_match + 1;
        right_index = right_match + 1;
    }
    while left_index < left_lines.len() {
        rows.push(removed_row(&left_lines, left_index));
        left_index += 1;
    }
    while right_index < right_lines.len() {
        rows.push(added_row(&right_lines, right_index));
        right_index += 1;
    }
    rows
}

fn removed_row(lines: &[&str], index: usize) -> CompareRow {
    CompareRow {
        kind: DiffKind::Removed,
        left_line: Some(index + 1),
        right_line: None,
        text: lines[index].to_string(),
        left_bytes: lines[index].len(),
        right_bytes: 0,
    }
}

fn added_row(lines: &[&str], index: usize) -> CompareRow {
    CompareRow {
        kind: DiffKind::Added,
        left_line: None,
        right_line: Some(index + 1),
        text: lines[index].to_string(),
        left_bytes: 0,
        right_bytes: lines[index].len(),
    }
}

/// Exact LCS as an ordered list of matching index pairs, with common
/// prefix/suffix trimming for the common fast paths.
fn lcs_hirschberg(left: &[&str], right: &[&str]) -> Vec<(usize, usize)> {
    let mut prefix = 0usize;
    while prefix < left.len() && prefix < right.len() && left[prefix] == right[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < left.len() - prefix
        && suffix < right.len() - prefix
        && left[left.len() - 1 - suffix] == right[right.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mut matches = Vec::new();
    for index in 0..prefix {
        matches.push((index, index));
    }
    let middle_left = &left[prefix..left.len() - suffix];
    let middle_right = &right[prefix..right.len() - suffix];
    hirschberg_recursion(middle_left, middle_right, prefix, prefix, &mut matches);
    for index in 0..suffix {
        matches.push((left.len() - suffix + index, right.len() - suffix + index));
    }
    matches
}

fn hirschberg_recursion(
    left: &[&str],
    right: &[&str],
    left_offset: usize,
    right_offset: usize,
    out: &mut Vec<(usize, usize)>,
) {
    if left.is_empty() || right.is_empty() {
        return;
    }
    if left.len() == 1 {
        if let Some(index) = right.iter().position(|candidate| *candidate == left[0]) {
            out.push((left_offset, right_offset + index));
        }
        return;
    }
    if right.len() == 1 {
        if let Some(index) = left.iter().position(|candidate| *candidate == right[0]) {
            out.push((left_offset + index, right_offset));
        }
        return;
    }

    let middle = left.len() / 2;
    let split_scores = lcs_lengths(&left[..middle], right);
    let left_tail: Vec<&str> = left[middle..].iter().rev().copied().collect();
    let right_reversed: Vec<&str> = right.iter().rev().copied().collect();
    let tail_scores = lcs_lengths(&left_tail, &right_reversed);

    let mut best_split = 0usize;
    let mut best_score = usize::MIN;
    for split in 0..=right.len() {
        let score = split_scores[split] + tail_scores[right.len() - split];
        if score > best_score {
            best_score = score;
            best_split = split;
        }
    }

    hirschberg_recursion(
        &left[..middle],
        &right[..best_split],
        left_offset,
        right_offset,
        out,
    );
    hirschberg_recursion(
        &left[middle..],
        &right[best_split..],
        left_offset + middle,
        right_offset + best_split,
        out,
    );
}

/// LCS score row: `scores[right_index]` is the LCS length of
/// `left` with `right[..right_index]`.
fn lcs_lengths(left: &[&str], right: &[&str]) -> Vec<usize> {
    let mut previous = vec![0usize; right.len() + 1];
    let mut current = vec![0usize; right.len() + 1];
    for left_line in left {
        current[0] = 0;
        for (right_index, right_line) in right.iter().enumerate() {
            current[right_index + 1] = if left_line == right_line {
                previous[right_index] + 1
            } else {
                previous[right_index + 1].max(current[right_index])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    #[test]
    fn incomplete_gamma_matches_known_values() {
        let close = |a: f64, b: f64| (a - b).abs() < 1e-6;
        // ln Gamma at integers and a half-integer.
        assert!(close(super::ln_gamma(1.0), 0.0), "{}", super::ln_gamma(1.0));
        assert!(close(super::ln_gamma(5.0), 24f64.ln()));
        assert!(close(
            super::ln_gamma(0.5),
            std::f64::consts::PI.sqrt().ln()
        ));
        // Q(1/2, x^2) = erfc(x).
        assert!(
            close(regularized_gamma_q(0.5, 0.25), 0.479_500_122),
            "{}",
            regularized_gamma_q(0.5, 0.25)
        );
        assert!(close(regularized_gamma_q(0.5, 1.0), 0.157_299_207));
        // Q(1, x) = exp(-x), on both the series and the continued-fraction side.
        assert!(close(regularized_gamma_q(1.0, 0.5), (-0.5f64).exp()));
        assert!(close(regularized_gamma_q(1.0, 5.0), (-5.0f64).exp()));
        // Chi-square: the 5% critical value for 1 degree of freedom is 3.841.
        assert!((chi_square_survival(3.841_458_8, 0.5) - 0.05).abs() < 1e-5);
        // ...and for 15 degrees of freedom is 24.996.
        assert!((chi_square_survival(24.995_790, 7.5) - 0.05).abs() < 1e-5);
    }

    use super::*;

    fn close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-12,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn empty_token_input_has_zero_stats() {
        let stats = analyze_tokens(&[]);
        assert_eq!(stats.sample_count, 0);
        assert_eq!(stats.token_length, 0);
        close(stats.bits_per_character, 0.0);
        close(stats.total_entropy_bits, 0.0);
        assert!(stats.char_distribution.is_empty());

        let stats = analyze_tokens(&[Vec::new(), Vec::new()]);
        assert_eq!(stats.sample_count, 2);
        assert_eq!(stats.token_length, 0);
        close(stats.bits_per_character, 0.0);
        close(stats.total_entropy_bits, 0.0);
        assert!(stats.char_distribution.is_empty());
    }

    #[test]
    fn token_entropy_matches_byte_frequencies() {
        // Four 'a' bytes and four 'b' bytes: one bit per byte, eight bits.
        let stats = analyze_tokens(&[b"aaaa".to_vec(), b"bbbb".to_vec()]);
        assert_eq!(stats.sample_count, 2);
        assert_eq!(stats.token_length, 4);
        close(stats.bits_per_character, 1.0);
        close(stats.total_entropy_bits, 8.0);
        assert_eq!(stats.char_distribution, vec![('a', 4), ('b', 4)]);
    }

    #[test]
    fn repeated_analysis_is_deterministic() {
        let samples = vec![b"abracadabra".to_vec(), b"alakazam".to_vec()];
        assert_eq!(analyze_tokens(&samples), analyze_tokens(&samples));
    }

    fn record(id: &str, tool: &str, title: &str, body: &str) -> SearchRecord {
        SearchRecord {
            id: id.to_string(),
            tool: tool.to_string(),
            title: title.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn search_respects_case_and_empty_query() {
        let records = vec![record("1", "Proxy", "Home", "Hello World")];
        assert!(search_records(true, "", &records).is_empty());
        assert!(search_records(true, "hello", &records).is_empty());
        let hits = search_records(false, "hello", &records);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, "1");
        assert_eq!(hits[0].excerpt, "Hello World");
    }

    #[test]
    fn search_falls_back_to_title_and_tool() {
        let records = vec![
            record("1", "Proxy", "Login form", "nothing here"),
            record("2", "Scanner", "Other", "nothing here"),
            record("3", "Repeater", "Other", "nothing here"),
        ];
        let hits = search_records(false, "login", &records);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, "1");
        assert_eq!(hits[0].excerpt, "Login form");

        let hits = search_records(false, "repeater", &records);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, "3");
        assert_eq!(hits[0].excerpt, "Repeater");
    }

    #[test]
    fn search_excerpt_is_bounded_and_contains_match() {
        let body = format!("{}needle{}", "prefix ".repeat(40), " suffix".repeat(40));
        let records = vec![record("1", "Proxy", "Title", &body)];
        let hits = search_records(false, "NEEDLE", &records);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].excerpt.contains("needle"));
        assert!(hits[0].excerpt.starts_with('…'));
        assert!(hits[0].excerpt.ends_with('…'));
    }

    #[test]
    fn search_handles_unicode_without_panicking() {
        let records = vec![record("1", "Proxy", "Über", "İstanbul αβγ needle δ\u{0}ε")];
        let hits = search_records(false, "needle", &records);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].excerpt.contains("needle"));
    }

    #[test]
    fn case_insensitive_excerpt_survives_lowercase_expansion() {
        // 70 'İ' expand to 140 folded characters; the folded offset must map
        // back to the original string or the 60-char window skips 'needle'.
        let body = format!("{} needle {}", "İ".repeat(70), "x".repeat(300));
        let records = vec![record("1", "Proxy", "Title", &body)];
        let hits = search_records(false, "needle", &records);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].excerpt.contains("needle"));
    }
}
