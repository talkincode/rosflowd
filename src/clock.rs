use chrono::{DateTime, TimeZone, Utc};

pub trait Clock {
    fn now_unix(&self) -> u32;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u32 {
        Utc::now().timestamp() as u32
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedClock {
    pub unix_secs: u32,
}

impl Clock for FixedClock {
    fn now_unix(&self) -> u32 {
        self.unix_secs
    }
}

pub fn day_utc(unix_secs: u32) -> String {
    Utc.timestamp_opt(i64::from(unix_secs), 0)
        .single()
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap())
        .format("%Y-%m-%d")
        .to_string()
}

pub fn hour_utc(unix_secs: u32) -> u32 {
    unix_secs / 3600 * 3600
}
