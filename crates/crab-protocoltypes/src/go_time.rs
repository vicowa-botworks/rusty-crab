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

/// Formats the instant `unix_seconds + nanos/1e9`, rendered in a fixed-offset
/// zone `offset_seconds` east of UTC, exactly as Go's `MarshalJSON` would.
///
/// `nanos` is the sub-second part in `[0, 1e9)` -- Go's `Time.Nanosecond()`, not
/// a signed remainder -- so a pre-epoch instant is a negative `unix_seconds`
/// with a non-negative fraction.
pub fn format_rfc3339_nano(unix_seconds: i64, nanos: u32, offset_seconds: i32) -> String {
    let local = unix_seconds as i128 + i128::from(offset_seconds);
    let days = div_floor(local, 86_400);
    let second_of_day = local - days * 86_400;
    let (year, month, day) = civil_from_days(days as i64);

    let mut out = String::with_capacity(35);
    // Go pads the year to a minimum of four digits and writes no upper bound,
    // so year 1 is "0001" and year 10000 would be "10000".
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

    if offset_seconds == 0 {
        out.push('Z');
    } else {
        let abs = offset_seconds.unsigned_abs();
        out.push(if offset_seconds < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}:{:02}", abs / 3_600, (abs % 3_600) / 60));
        // Go's RFC3339 writer only appends seconds when the offset has them;
        // such zones are legal in a tz database and would otherwise be silently
        // rounded to the nearest minute.
        if !abs.is_multiple_of(60) {
            out.push_str(&format!(":{:02}", abs % 60));
        }
    }
    out
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

    #[test]
    fn epoch_and_day_boundaries() {
        assert_eq!(format_rfc3339_nano(0, 0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_nano(-1, 0, 0), "1969-12-31T23:59:59Z");
        assert_eq!(format_rfc3339_nano(-86_400, 0, 0), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn the_fraction_drops_trailing_zeros() {
        assert_eq!(
            format_rfc3339_nano(0, 1, 0),
            "1970-01-01T00:00:00.000000001Z"
        );
        assert_eq!(
            format_rfc3339_nano(0, 100_000_000, 0),
            "1970-01-01T00:00:00.1Z"
        );
        assert_eq!(
            format_rfc3339_nano(0, 123_456_789, 0),
            "1970-01-01T00:00:00.123456789Z"
        );
        assert_eq!(
            format_rfc3339_nano(0, 1_000_000, 0),
            "1970-01-01T00:00:00.001Z"
        );
    }

    #[test]
    fn offsets_and_the_zero_offset_letter() {
        assert_eq!(
            format_rfc3339_nano(0, 0, 19_800),
            "1970-01-01T05:30:00+05:30"
        );
        assert_eq!(
            format_rfc3339_nano(0, 0, -25_200),
            "1969-12-31T17:00:00-07:00"
        );
        // A zone with seconds in it keeps them rather than rounding.
        assert_eq!(
            format_rfc3339_nano(0, 0, 19_801),
            "1970-01-01T05:30:01+05:30:01"
        );
    }

    #[test]
    fn the_zero_time_and_the_far_future() {
        // Go's zero time.Time, which session files contain.
        assert_eq!(
            format_rfc3339_nano(-62_135_596_800, 0, 0),
            "0001-01-01T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339_nano(253_402_300_799, 999_999_999, 0),
            "9999-12-31T23:59:59.999999999Z"
        );
    }

    #[test]
    fn leap_day_and_the_centuries() {
        // 2000 is a leap year (divisible by 400), 1900 is not.
        assert_eq!(
            format_rfc3339_nano(951_782_400, 0, 0),
            "2000-02-29T00:00:00Z"
        );
        let _ = 1900;
    }

    #[test]
    fn a_negative_instant_with_a_positive_fraction() {
        // Go's Unix()/Nanosecond() pair for 0.5s before the epoch is (-1, 5e8),
        // not (-0.5s expressed as a single negative count).
        assert_eq!(
            format_rfc3339_nano(-1, 500_000_000, 0),
            "1969-12-31T23:59:59.5Z"
        );
    }
}
