//! Local time as the Python client prints it. On unix this asks the C library for the local
//! zone; elsewhere it falls back to UTC (`Z`).

use std::time::{SystemTime, UNIX_EPOCH};

/// A broken-down local time.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// Seconds east of UTC.
    pub offset: i64,
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// UTC time for a unix timestamp.
pub fn utc(ts: i64) -> Local {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil(days);
    Local { year, month, day, hour: (secs / 3600) as u32, minute: (secs % 3600 / 60) as u32, second: (secs % 60) as u32, offset: 0 }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn local(ts: i64) -> Local {
    // SAFETY: `tm` is plain data, zeroed before use; `localtime_r` only writes into it.
    let tm = unsafe {
        let t: libc::time_t = ts as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return utc(ts);
        }
        tm
    };
    Local {
        year: i64::from(tm.tm_year) + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        second: tm.tm_sec as u32,
        #[allow(clippy::useless_conversion)]
        offset: i64::from(tm.tm_gmtoff),
    }
}

#[cfg(not(unix))]
fn local(ts: i64) -> Local {
    utc(ts)
}

/// Now, in local time.
pub fn now() -> Local {
    local(unix_now())
}

impl Local {
    /// `YYYYMMDD-HHMMSS`.
    pub fn stamp(&self) -> String {
        format!("{:04}{:02}{:02}-{:02}{:02}{:02}", self.year, self.month, self.day, self.hour, self.minute, self.second)
    }

    /// ISO 8601 to the second, with the offset (`Z` for UTC).
    pub fn iso(&self) -> String {
        let date = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", self.year, self.month, self.day, self.hour, self.minute, self.second);
        if self.offset == 0 {
            return format!("{date}Z");
        }
        let sign = if self.offset < 0 { '-' } else { '+' };
        let abs = self.offset.abs();
        format!("{date}{sign}{:02}:{:02}", abs / 3600, abs % 3600 / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formats() {
        let t = utc(1_791_000_000);
        assert_eq!(t.stamp(), "20261003-040000");
        assert_eq!(t.iso(), "2026-10-03T04:00:00Z");
        assert_eq!(utc(0).iso(), "1970-01-01T00:00:00Z");
    }
}
