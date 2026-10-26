//! Go's `time.Time` wire format.
//!
//! `time.Time.MarshalJSON` emits RFC3339 with nanoseconds, and the nanosecond
//! part is what catches a port: Go writes the fraction with **trailing zeros
//! removed**, so an exact second has no fraction at all and `100000000` ns is
//! written `.1`. A fixed-width formatter -- including `chrono`'s default
//! `to_rfc3339()`, which picks 0, 3 or 6 digits -- produces `.100000` and is
//! wrong.
//!
//! The instant arrives as `unix_seconds` plus `nanos` rather than as a packed
//! count, because Go's `UnixNano` is only defined between 1678 and 2262 while the
//! zero `time.Time` (year 1) does appear in session files.
//!
//! Two of Go's rules are refusals rather than formatting, and this module
//! reproduces them as [`MarshalError`] so the whole document fails the way
//! `json.Marshal` fails it:
//!
//! * the year must be in `[0, 9999]` -- `appendStrictRFC3339` checks the width
//!   and returns `year outside of range [0,9999]`;
//! * the zone hour must be in `[0, 23]` -- `timezone hour outside of range
//!   [0,23]`.
//!
//! The offset is also written in **whole minutes only**: `appendFormatRFC3339`
//! divides by 60 before formatting, so a zone with seconds in it prints `+05:30`
//! while its wall clock keeps the seconds, and a sub-minute negative offset
//! takes its sign after that truncation and prints `+00:00`.

use crab_gojson::MarshalError;

/// Formats the instant `unix_seconds + nanos/1e9`, rendered in a fixed-offset
/// zone `offset_seconds` east of UTC, exactly as Go's `MarshalJSON` would.
///
/// `nanos` is the sub-second part in `[0, 1e9)` -- Go's `Time.Nanosecond()`, not
/// a signed remainder -- so a pre-epoch instant is a negative `unix_seconds`
/// with a non-negative fraction.
///
/// Fails, with Go's own message, for the instants Go refuses to marshal: a year
/// outside `[0, 9999]` or a zone hour outside `[0, 23]`. The payload is Go's
/// inner message; Go itself wraps it as `json: error calling MarshalJSON for
/// type *time.Time: <message>`, and `MarshalError`'s `Display` renders a
/// different wrapper again -- see `docs/DIVERGENCES.md`.
pub fn format_rfc3339_nano(
    unix_seconds: i64,
    nanos: u32,
    offset_seconds: i32,
) -> Result<String, MarshalError> {
    let offset = i64::from(offset_seconds);
    if offset.unsigned_abs() / 3_600 > 23 {
        return Err(MarshalError("timezone hour outside of range [0,23]".into()));
    }

    let local = i128::from(unix_seconds) + i128::from(offset);
    let days = div_floor(local, 86_400);
    let second_of_day = local - days * 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    if !(0..=9_999).contains(&year) {
        return Err(MarshalError("year outside of range [0,9999]".into()));
    }

    let mut out = String::with_capacity(35);
    out.push_str(&format!("{year:04}-{month:02}-{day:02}T"));
    out.push_str(&format!(
        "{:02}:{:02}:{:02}",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60,
    ));

    if nanos != 0 {
        // Nine digits, then Go's format drops the trailing zeros.
        let frac = format!("{nanos:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }

    if offset == 0 {
        out.push('Z');
    } else {
        // Whole minutes only: Go divides the offset by 60 before it formats it,
        // so a legal zone with seconds in it (LMT-style, or a hand-built
        // FixedZone) prints +05:30 while its clock reads 05:30:01. Taking the
        // sign from the truncated minutes is what makes a sub-minute negative
        // offset print +00:00 rather than -00:00.
        let minutes = offset / 60;
        let abs = minutes.unsigned_abs();
        out.push(if minutes < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}:{:02}", abs / 60, abs % 60));
    }
    Ok(out)
}

/// Floor division, which Rust's `/` is not: Go's integer division truncates, but
/// the day arithmetic below must put 1969-12-31 on the day *before* the epoch.
fn div_floor(a: i128, b: i128) -> i128 {
    let q = a / b;
    if a % b != 0 && (a < 0) != (b < 0) {
        q - 1
    } else {
        q
    }
}

/// Days since 19400-01-01 shifted epoch: Howard Hinnant's `civil_from_days`,
/// which is exact over the whole proleptic Gregorian calendar and so needs no
/// table and no special case for dates before 1970.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = div_floor(i128::from(z), 146_097) as i64;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    // The year starts in March inside this numbering, so January and February
    // belong to the next year.
    let year = if month <= 2 { y + 1 } else { y };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(unix_seconds: i64, nanos: u32, offset_seconds: i32) -> String {
        format_rfc3339_nano(unix_seconds, nanos, offset_seconds).unwrap()
    }

    #[test]
    fn epoch_and_day_boundaries() {
        assert_eq!(fmt(0, 0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt(-1, 0, 0), "1969-12-31T23:59:59Z");
        assert_eq!(fmt(-86_400, 0, 0), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn the_fraction_drops_trailing_zeros() {
        assert_eq!(fmt(0, 1, 0), "1970-01-01T00:00:00.000000001Z");
        assert_eq!(fmt(0, 100_000_000, 0), "1970-01-01T00:00:00.1Z");
        assert_eq!(fmt(0, 123_456_789, 0), "1970-01-01T00:00:00.123456789Z");
        assert_eq!(fmt(0, 1_000_000, 0), "1970-01-01T00:00:00.001Z");
    }

    #[test]
    fn offsets_and_the_zero_offset_letter() {
        assert_eq!(fmt(0, 0, 19_800), "1970-01-01T05:30:00+05:30");
        assert_eq!(fmt(0, 0, -25_200), "1969-12-31T17:00:00-07:00");
        assert_eq!(fmt(0, 0, 45_900), "1970-01-01T12:45:00+12:45");
    }

    #[test]
    fn the_offset_is_whole_minutes_only() {
        // Go's appendFormatRFC3339 does `zone := offset / 60` and writes hour
        // and minute -- there is no seconds term to write. The clock keeps the
        // seconds; the printed offset does not. Measured against go1.27.2
        // through json.Marshal of a time.Time in time.FixedZone.
        assert_eq!(fmt(0, 0, 19_801), "1970-01-01T05:30:01+05:30");
        assert_eq!(fmt(0, 0, 3_661), "1970-01-01T01:01:01+01:01");
        assert_eq!(fmt(0, 0, 45_901), "1970-01-01T12:45:01+12:45");
        // The sign is taken after the truncation, so a sub-minute negative
        // offset is a zero minute and prints positive.
        assert_eq!(fmt(0, 0, -1), "1969-12-31T23:59:59+00:00");
        assert_eq!(fmt(0, 0, -59), "1969-12-31T23:59:01+00:00");
        // One full minute does flip the sign.
        assert_eq!(fmt(0, 0, -60), "1969-12-31T23:59:00-00:01");
    }

    #[test]
    fn go_refuses_years_outside_the_four_digit_window() {
        // appendStrictRFC3339 checks the width and fails the whole document;
        // json.Marshal then returns no bytes at all.
        assert_eq!(fmt(-62_135_596_800, 0, 0), "0001-01-01T00:00:00Z");
        assert_eq!(fmt(-62_167_219_200, 0, 0), "0000-01-01T00:00:00Z");
        assert_eq!(
            fmt(253_402_300_799, 999_999_999, 0),
            "9999-12-31T23:59:59.999999999Z"
        );
        // Compared on the payload: MarshalError's Display adds the encoder's
        // generic "json: unsupported value:" wrapper, which is Go's wording for
        // the NaN/Inf family, not for a MarshalJSON refusal.
        let err = format_rfc3339_nano(253_402_300_800, 0, 0).unwrap_err();
        assert_eq!(err.0, "year outside of range [0,9999]");
        let err = format_rfc3339_nano(-62_167_263_361, 0, 0).unwrap_err();
        assert_eq!(err.0, "year outside of range [0,9999]");
    }

    #[test]
    fn go_refuses_a_zone_hour_past_23() {
        assert_eq!(fmt(0, 0, 86_399), "1970-01-01T23:59:59+23:59");
        assert_eq!(fmt(0, 0, -86_399), "1969-12-31T00:00:01-23:59");
        for off in [86_400, -86_400, i32::MAX, i32::MIN] {
            let err = format_rfc3339_nano(0, 0, off).unwrap_err();
            assert_eq!(err.0, "timezone hour outside of range [0,23]");
        }
    }

    #[test]
    fn leap_day_and_the_centuries() {
        // 2000 is a leap year (divisible by 400), 1900 is not.
        assert_eq!(fmt(951_782_400, 0, 0), "2000-02-29T00:00:00Z");
        let _ = 1900;
    }

    #[test]
    fn a_negative_instant_with_a_positive_fraction() {
        // Go's Unix()/Nanosecond() pair for 0.5s before the epoch is (-1, 5e8),
        // not (-0.5s expressed as a single negative count).
        assert_eq!(fmt(-1, 500_000_000, 0), "1969-12-31T23:59:59.5Z");
    }
}
