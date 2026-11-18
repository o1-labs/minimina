//! Times as minimina reads and writes them: RFC 3339, keeping the offset a
//! time was written with, so a time read and written again is the same text.

use jiff::{
    fmt::temporal::{DateTimePrinter, Pieces, PiecesOffset},
    tz::{Offset, TimeZone},
    Timestamp, ZonedDateTime,
};

/// Now, at the local offset of now. The offset stays with the time: adding
/// to it never moves to another offset, as a time zone's rules would.
pub fn now() -> ZonedDateTime {
    let now = ZonedDateTime::now();
    let offset = now.offset();
    now.with_time_zone(TimeZone::fixed(offset))
}

/// [`now`] in RFC 3339.
pub fn now_rfc3339() -> String {
    rfc3339(&now())
}

/// An RFC 3339 time (`2026-10-29T12:00:00+01:00`), at its own offset.
pub fn parse(text: &str) -> Result<ZonedDateTime, jiff::Error> {
    let offset = match Pieces::parse(text)?.offset() {
        Some(PiecesOffset::Zulu) => Offset::UTC,
        Some(PiecesOffset::Numeric(numeric)) => numeric.offset(),
        _ => {
            return Err(jiff::Error::from_args(format_args!(
                "'{text}' has no UTC offset"
            )))
        }
    };
    let timestamp: Timestamp = text.parse()?;
    Ok(timestamp.to_zoned_datetime(TimeZone::fixed(offset)))
}

/// `time` in RFC 3339, with the fraction of a second only to the digits it
/// needs: none, 3, 6 or 9.
pub fn rfc3339(time: &ZonedDateTime) -> String {
    let nanos = time.timestamp().subsec_nanosecond();
    let digits = match nanos {
        0 => 0,
        n if n % 1_000_000 == 0 => 3,
        n if n % 1_000 == 0 => 6,
        _ => 9,
    };
    print(time, digits)
}

/// `time` in RFC 3339, to the microsecond: how mina writes a
/// `genesis_state_timestamp`.
pub fn rfc3339_micros(time: &ZonedDateTime) -> String {
    print(time, 6)
}

fn print(time: &ZonedDateTime, digits: u8) -> String {
    DateTimePrinter::new()
        .precision(Some(digits))
        .timestamp_with_offset_to_string(&time.timestamp(), time.offset())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;

    #[test]
    fn writes_a_time_back_as_it_was_read() {
        for text in [
            "2026-10-29T12:00:00+01:00",
            "2026-11-12T00:46:59.717+00:00",
            "2023-09-20T17:20:57.897531+02:00",
            "2023-09-20T17:20:57.897531200-05:30",
        ] {
            assert_eq!(rfc3339(&parse(text).unwrap()), text);
        }
        assert_eq!(
            rfc3339(&parse("2026-11-12T00:46:59.717Z").unwrap()),
            "2026-11-12T00:46:59.717+00:00"
        );
    }

    #[test]
    fn keeps_the_offset_when_time_moves() {
        let genesis = parse("2026-10-29T12:00:00+01:00").unwrap();
        let later = &genesis + SignedDuration::from_millis(12_345);
        assert_eq!(rfc3339(&later), "2026-10-29T12:00:12.345+01:00");
        assert_eq!(later.duration_since(&genesis).as_millis(), 12_345);
    }

    #[test]
    fn writes_genesis_timestamps_to_the_microsecond() {
        let genesis = parse("2026-10-29T12:00:00.5+01:00").unwrap();
        assert_eq!(rfc3339_micros(&genesis), "2026-10-29T12:00:00.500000+01:00");
    }

    #[test]
    fn a_time_needs_an_offset() {
        let error = parse("2026-10-29T12:00:00").unwrap_err();
        assert!(error.to_string().contains("no UTC offset"), "{error}");
        assert!(parse("yesterday").is_err());
    }
}
