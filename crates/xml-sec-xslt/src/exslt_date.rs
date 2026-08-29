use std::sync::Arc;

use sxd_xpath_no_unsafe::{Context, Value, function};

use crate::{Clock, ExtensionPolicy};

pub(crate) const NAMESPACE: &str = "http://exslt.org/dates-and-times";
pub(crate) fn register(
    context: &mut Context<'_>,
    clock: Arc<dyn Clock>,
    extension_policy: ExtensionPolicy,
) {
    for &(name, operation) in FUNCTIONS {
        context.set_function(
            (NAMESPACE, name),
            DateFunction(operation, Arc::clone(&clock), extension_policy),
        );
    }
}

pub(crate) fn function_names() -> impl Iterator<Item = &'static str> {
    FUNCTIONS.iter().map(|(name, _)| *name)
}

const FUNCTIONS: &[(&str, Operation)] = &[
    ("year", Operation::Year),
    ("leap-year", Operation::LeapYear),
    ("month-in-year", Operation::MonthInYear),
    ("month-name", Operation::MonthName),
    ("month-abbreviation", Operation::MonthAbbreviation),
    ("week-in-year", Operation::WeekInYear),
    ("day-in-year", Operation::DayInYear),
    ("day-in-month", Operation::DayInMonth),
    ("day-of-week-in-month", Operation::DayOfWeekInMonth),
    ("day-in-week", Operation::DayInWeek),
    ("day-name", Operation::DayName),
    ("day-abbreviation", Operation::DayAbbreviation),
    ("time", Operation::Time),
    ("hour-in-day", Operation::HourInDay),
    ("minute-in-hour", Operation::MinuteInHour),
    ("second-in-minute", Operation::SecondInMinute),
    ("seconds", Operation::Seconds),
    ("duration", Operation::Duration),
    ("add-duration", Operation::AddDuration),
    ("sum", Operation::Sum),
    ("add", Operation::Add),
    ("difference", Operation::Difference),
];

#[derive(Clone, Copy)]
enum Operation {
    Year,
    LeapYear,
    MonthInYear,
    MonthName,
    MonthAbbreviation,
    WeekInYear,
    DayInYear,
    DayInMonth,
    DayOfWeekInMonth,
    DayInWeek,
    DayName,
    DayAbbreviation,
    Time,
    HourInDay,
    MinuteInHour,
    SecondInMinute,
    Seconds,
    Duration,
    AddDuration,
    Sum,
    Add,
    Difference,
}

struct DateFunction(Operation, Arc<dyn Clock>, ExtensionPolicy);

impl function::Function for DateFunction {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> std::result::Result<Value<'d>, function::Error> {
        use Operation::*;
        match self.0 {
            AddDuration | Add | Difference if args.len() != 2 => {
                return argument_error("requires two arguments");
            }
            Sum if args.len() != 1 => return argument_error("requires one argument"),
            AddDuration | Add | Difference | Sum => {}
            _ if args.len() > 1 => return argument_error("requires zero or one argument"),
            _ => {}
        }
        match self.0 {
            Sum => {
                let Value::Nodeset(nodes) = &args[0] else {
                    return argument_error("date:sum() requires a node-set");
                };
                if nodes.size() == 0 {
                    return Ok(Value::String(String::new()));
                }
                let mut total = DurationValue::default();
                for node in nodes.document_order() {
                    let Some(value) = DurationValue::parse(&node.string_value()) else {
                        return Ok(Value::String(String::new()));
                    };
                    let Some(sum) = total.checked_add(value) else {
                        return Ok(Value::String(String::new()));
                    };
                    total = sum;
                }
                Ok(Value::String(total.render()))
            }
            AddDuration => {
                let Some(left) = DurationValue::parse(&args[0].string()) else {
                    return Ok(Value::String(String::new()));
                };
                let Some(right) = DurationValue::parse(&args[1].string()) else {
                    return Ok(Value::String(String::new()));
                };
                Ok(Value::String(
                    left.checked_add(right)
                        .map_or_else(String::new, DurationValue::render),
                ))
            }
            Duration => Ok(Value::String(
                args.first()
                    .map(Value::number)
                    .filter(|seconds| seconds.is_finite() && seconds.abs() < 1e23)
                    .map(DurationValue::from_seconds)
                    .map_or_else(String::new, DurationValue::render),
            )),
            Seconds => {
                let input = args.first().map(Value::string).unwrap_or_default();
                let seconds = DurationValue::parse(&input)
                    .filter(|duration| duration.months == 0)
                    .map(|duration| duration.seconds)
                    .or_else(|| DateValue::parse(&input).and_then(DateValue::unix_seconds))
                    .unwrap_or(f64::NAN);
                Ok(Value::Number(seconds))
            }
            Add => {
                let Some(date) = DateValue::parse(&args[0].string()) else {
                    return Ok(Value::String(String::new()));
                };
                let Some(duration) = DurationValue::parse(&args[1].string()) else {
                    return Ok(Value::String(String::new()));
                };
                Ok(Value::String(
                    date.add(duration)
                        .map_or_else(String::new, |date| date.render()),
                ))
            }
            Difference => {
                let Some(left) = DateValue::parse(&args[0].string()) else {
                    return Ok(Value::String(String::new()));
                };
                let Some(right) = DateValue::parse(&args[1].string()) else {
                    return Ok(Value::String(String::new()));
                };
                Ok(Value::String(
                    left.difference(right)
                        .map_or_else(String::new, DurationValue::render),
                ))
            }
            operation => {
                let input = args.first().map(Value::string);
                let current;
                let input = if let Some(input) = input.as_deref() {
                    input
                } else {
                    if self.2 == ExtensionPolicy::Deterministic {
                        return argument_error(
                            "zero-argument EXSLT date functions are disabled by the execution extension policy",
                        );
                    }
                    current = current_datetime(self.1.as_ref())?;
                    &current
                };
                evaluate_component(operation, Some(input))
            }
        }
    }
}

fn current_datetime(clock: &dyn Clock) -> std::result::Result<String, function::Error> {
    let current = clock.now_local().map_err(|error| function::Error::Other {
        what: error.to_string(),
    })?;
    let offset = current.offset().whole_seconds();
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.unsigned_abs();
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        current.year(),
        u8::from(current.month()),
        current.day(),
        current.hour(),
        current.minute(),
        current.second(),
        offset / 3600,
        (offset % 3600) / 60,
    ))
}

fn evaluate_component(
    operation: Operation,
    input: Option<&str>,
) -> std::result::Result<Value<'static>, function::Error> {
    let Some(date) = input.and_then(DateValue::parse) else {
        return Ok(match operation {
            Operation::MonthName
            | Operation::MonthAbbreviation
            | Operation::DayName
            | Operation::DayAbbreviation
            | Operation::Time => Value::String(String::new()),
            _ => Value::Number(f64::NAN),
        });
    };
    let number = |value: Option<i64>| Value::Number(value.map_or(f64::NAN, |value| value as f64));
    let kind_is = |kinds: &[DateKind]| kinds.contains(&date.kind);
    Ok(match operation {
        Operation::Year => number(
            kind_is(DateKind::YEAR_BEARING)
                .then_some(date.year)
                .flatten(),
        ),
        Operation::LeapYear => kind_is(DateKind::YEAR_BEARING)
            .then_some(date.year)
            .flatten()
            .map_or(Value::Number(f64::NAN), |year| {
                Value::Boolean(is_leap(year))
            }),
        Operation::MonthInYear => number(
            kind_is(DateKind::MONTH_BEARING)
                .then_some(date.month)
                .flatten()
                .map(i64::from),
        ),
        Operation::MonthName => Value::String(
            kind_is(DateKind::MONTH_NAME_BEARING)
                .then_some(date.month)
                .flatten()
                .map(month_name)
                .unwrap_or_default()
                .into(),
        ),
        Operation::MonthAbbreviation => Value::String(
            kind_is(DateKind::MONTH_NAME_BEARING)
                .then_some(date.month)
                .flatten()
                .map(month_name)
                .map(|name| &name[..3])
                .unwrap_or_default()
                .into(),
        ),
        Operation::WeekInYear => number(
            kind_is(DateKind::COMPLETE_DATE)
                .then(|| date.complete_date())
                .flatten()
                .map(|(y, m, d)| i64::from(iso_week(y, m, d))),
        ),
        Operation::DayInYear => number(
            kind_is(DateKind::COMPLETE_DATE)
                .then(|| date.complete_date())
                .flatten()
                .map(|(y, m, d)| i64::from(ordinal(y, m, d))),
        ),
        Operation::DayInMonth => number(
            kind_is(DateKind::DAY_BEARING)
                .then_some(date.day)
                .flatten()
                .map(i64::from),
        ),
        Operation::DayOfWeekInMonth => number(
            kind_is(DateKind::COMPLETE_DATE)
                .then_some(date.day)
                .flatten()
                .map(|day| i64::from((day - 1) / 7 + 1)),
        ),
        Operation::DayInWeek => number(
            kind_is(DateKind::COMPLETE_DATE)
                .then(|| date.complete_date())
                .flatten()
                .map(|(y, m, d)| i64::from(weekday(y, m, d) + 1)),
        ),
        Operation::DayName => Value::String(
            kind_is(DateKind::COMPLETE_DATE)
                .then(|| date.complete_date())
                .flatten()
                .map(|(y, m, d)| day_name(weekday(y, m, d)))
                .unwrap_or_default()
                .into(),
        ),
        Operation::DayAbbreviation => Value::String(
            kind_is(DateKind::COMPLETE_DATE)
                .then(|| date.complete_date())
                .flatten()
                .map(|(y, m, d)| &day_name(weekday(y, m, d))[..3])
                .unwrap_or_default()
                .into(),
        ),
        Operation::Time => Value::String(
            kind_is(DateKind::TIME_BEARING)
                .then(|| date.time_string())
                .flatten()
                .unwrap_or_default(),
        ),
        Operation::HourInDay => number(
            kind_is(DateKind::TIME_BEARING)
                .then_some(date.hour)
                .flatten()
                .map(i64::from),
        ),
        Operation::MinuteInHour => number(
            kind_is(DateKind::TIME_BEARING)
                .then_some(date.minute)
                .flatten()
                .map(i64::from),
        ),
        Operation::SecondInMinute => kind_is(DateKind::TIME_BEARING)
            .then_some(date.second)
            .flatten()
            .map_or(Value::Number(f64::NAN), Value::Number),
        _ => unreachable!("non-component operation was handled by the caller"),
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct DurationValue {
    months: i64,
    seconds: f64,
}

impl DurationValue {
    fn parse(input: &str) -> Option<Self> {
        let (sign, input) = input
            .strip_prefix('-')
            .map_or((1.0, input), |rest| (-1.0, rest));
        let mut rest = input.strip_prefix('P')?;
        if rest.is_empty() {
            return None;
        }
        let mut result = Self::default();
        let mut in_time = false;
        let mut saw = false;
        let mut last_rank = 0;
        while !rest.is_empty() {
            if let Some(after) = rest.strip_prefix('T') {
                if in_time || after.is_empty() {
                    return None;
                }
                in_time = true;
                last_rank = 3;
                rest = after;
                continue;
            }
            let end =
                rest.find(|character: char| !(character.is_ascii_digit() || character == '.'))?;
            if end == 0 {
                return None;
            }
            let value = rest[..end].parse::<f64>().ok()?;
            if !value.is_finite() {
                return None;
            }
            let designator = rest[end..].chars().next()?;
            let rank = match (in_time, designator) {
                (false, 'Y') => 1,
                (false, 'M') => 2,
                (false, 'D') => 3,
                (true, 'H') => 4,
                (true, 'M') => 5,
                (true, 'S') => 6,
                _ => return None,
            };
            if rank <= last_rank || (rank != 6 && value.fract() != 0.0) {
                return None;
            }
            match rank {
                1 => result.months = result.months.checked_add((value as i64).checked_mul(12)?)?,
                2 => result.months = result.months.checked_add(value as i64)?,
                3 => result.seconds += value * 86_400.0,
                4 => result.seconds += value * 3_600.0,
                5 => result.seconds += value * 60.0,
                6 => result.seconds += value,
                _ => unreachable!(),
            }
            saw = true;
            last_rank = rank;
            rest = &rest[end + designator.len_utf8()..];
        }
        saw.then_some(Self {
            months: (result.months as f64 * sign) as i64,
            seconds: result.seconds * sign,
        })
    }

    fn from_seconds(seconds: f64) -> Self {
        Self { months: 0, seconds }
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let months = self.months.checked_add(other.months)?;
        let seconds = self.seconds + other.seconds;
        ((months == 0 || seconds == 0.0 || months.signum() as f64 == seconds.signum())
            && seconds.is_finite())
        .then_some(Self { months, seconds })
    }

    fn render(self) -> String {
        if self.months == 0 && self.seconds == 0.0 {
            return "P0D".into();
        }
        let negative = self.months < 0 || self.seconds < 0.0;
        let months = self.months.unsigned_abs();
        let mut seconds = self.seconds.abs();
        let rounded = seconds.round();
        if (seconds - rounded).abs() < 1e-9 {
            seconds = rounded;
        }
        let days = (seconds / 86_400.0).floor() as u64;
        seconds -= days as f64 * 86_400.0;
        let hours = (seconds / 3_600.0).floor() as u64;
        seconds -= hours as f64 * 3_600.0;
        let minutes = (seconds / 60.0).floor() as u64;
        seconds -= minutes as f64 * 60.0;
        let mut output = if negative {
            "-P".to_owned()
        } else {
            "P".to_owned()
        };
        if months / 12 != 0 {
            output.push_str(&format!("{}Y", months / 12));
        }
        if !months.is_multiple_of(12) {
            output.push_str(&format!("{}M", months % 12));
        }
        if days != 0 {
            output.push_str(&format!("{days}D"));
        }
        if hours != 0 || minutes != 0 || seconds != 0.0 {
            output.push('T');
            if hours != 0 {
                output.push_str(&format!("{hours}H"));
            }
            if minutes != 0 {
                output.push_str(&format!("{minutes}M"));
            }
            if seconds != 0.0 {
                output.push_str(&format!("{}S", trim_float(seconds)));
            }
        }
        output
    }
}

#[derive(Clone, Debug)]
struct DateValue {
    year: Option<i64>,
    month: Option<u8>,
    day: Option<u8>,
    hour: Option<u8>,
    minute: Option<u8>,
    second: Option<f64>,
    timezone: Option<i32>,
    kind: DateKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DateKind {
    Year,
    YearMonth,
    Date,
    DateTime,
    Month,
    MonthDay,
    Day,
    Time,
}

impl DateKind {
    const YEAR_BEARING: &[Self] = &[Self::Year, Self::YearMonth, Self::Date, Self::DateTime];
    const MONTH_BEARING: &[Self] = &[
        Self::YearMonth,
        Self::Date,
        Self::DateTime,
        Self::Month,
        Self::MonthDay,
    ];
    const MONTH_NAME_BEARING: &[Self] = &[
        Self::YearMonth,
        Self::Date,
        Self::DateTime,
        Self::Month,
        Self::MonthDay,
    ];
    const COMPLETE_DATE: &[Self] = &[Self::Date, Self::DateTime];
    const DAY_BEARING: &[Self] = &[Self::Date, Self::DateTime, Self::MonthDay, Self::Day];
    const TIME_BEARING: &[Self] = &[Self::DateTime, Self::Time];
}

impl DateValue {
    fn parse(input: &str) -> Option<Self> {
        let (body, timezone) = split_timezone(input)?;
        let empty = Self {
            year: None,
            month: None,
            day: None,
            hour: None,
            minute: None,
            second: None,
            timezone,
            kind: DateKind::Year,
        };
        if let Some(day) = body.strip_prefix("---") {
            let day = parse_two(day)?;
            return (1..=31).contains(&day).then_some(Self {
                day: Some(day),
                kind: DateKind::Day,
                ..empty
            });
        }
        if let Some(value) = body.strip_prefix("--") {
            if let Some(month) = value.strip_suffix("--") {
                let month = parse_two(month)?;
                return (1..=12).contains(&month).then_some(Self {
                    month: Some(month),
                    kind: DateKind::Month,
                    ..empty
                });
            }
            let (month, day) = value.split_once('-')?;
            let (month, day) = (parse_two(month)?, parse_two(day)?);
            return valid_day(2000, month, day).then_some(Self {
                month: Some(month),
                day: Some(day),
                kind: DateKind::MonthDay,
                ..empty
            });
        }
        if body.contains(':') && !body.contains('T') {
            let (hour, minute, second) = parse_time(body)?;
            return Some(Self {
                hour: Some(hour),
                minute: Some(minute),
                second: Some(second),
                kind: DateKind::Time,
                ..empty
            });
        }
        let (date, time) = body
            .split_once('T')
            .map_or((body, None), |(date, time)| (date, Some(time)));
        let (year, tail) = parse_year(date)?;
        let Some(tail) = tail.strip_prefix('-') else {
            return (time.is_none()).then_some(Self {
                year: Some(year),
                kind: DateKind::Year,
                ..empty
            });
        };
        let (month, tail) = if let Some((month, tail)) = tail.split_once('-') {
            (parse_two(month)?, Some(tail))
        } else {
            (parse_two(tail)?, None)
        };
        if !(1..=12).contains(&month) {
            return None;
        }
        let Some(day) = tail else {
            return (time.is_none()).then_some(Self {
                year: Some(year),
                month: Some(month),
                kind: DateKind::YearMonth,
                ..empty
            });
        };
        let day = parse_two(day)?;
        if !valid_day(year, month, day) {
            return None;
        }
        if let Some(time) = time {
            let (hour, minute, second) = parse_time(time)?;
            Some(Self {
                year: Some(year),
                month: Some(month),
                day: Some(day),
                hour: Some(hour),
                minute: Some(minute),
                second: Some(second),
                kind: DateKind::DateTime,
                ..empty
            })
        } else {
            Some(Self {
                year: Some(year),
                month: Some(month),
                day: Some(day),
                kind: DateKind::Date,
                ..empty
            })
        }
    }

    fn complete_date(&self) -> Option<(i64, u8, u8)> {
        Some((self.year?, self.month?, self.day?))
    }
    fn time_string(&self) -> Option<String> {
        let (hour, minute, second) = (self.hour?, self.minute?, self.second?);
        Some(format!(
            "{hour:02}:{minute:02}:{}{}",
            format_second(second),
            render_timezone(self.timezone)
        ))
    }
    fn unix_seconds(self) -> Option<f64> {
        if !DateKind::YEAR_BEARING.contains(&self.kind) {
            return None;
        }
        let year = self.year?;
        let month = self.month.unwrap_or(1);
        let day = self.day.unwrap_or(1);
        let days = days_from_civil(year, month, day) - days_from_civil(1970, 1, 1);
        let time = f64::from(self.hour.unwrap_or(0)) * 3600.0
            + f64::from(self.minute.unwrap_or(0)) * 60.0
            + self.second.unwrap_or(0.0);
        Some(days as f64 * 86_400.0 + time - f64::from(self.timezone.unwrap_or(0)))
    }
    fn difference(self, other: Self) -> Option<DurationValue> {
        let specificity = |kind| match kind {
            DateKind::Year => Some(0),
            DateKind::YearMonth => Some(1),
            DateKind::Date => Some(2),
            DateKind::DateTime => Some(3),
            _ => None,
        };
        let least = specificity(self.kind)?.min(specificity(other.kind)?);
        if least <= 1 {
            let serial_month = |date: &Self| {
                astronomical_year(date.year?)
                    .checked_mul(12)?
                    .checked_add(i64::from(date.month.unwrap_or(1)) - 1)
            };
            let months = serial_month(&other)?.checked_sub(serial_month(&self)?)?;
            return Some(DurationValue {
                months: if least == 0 { months / 12 * 12 } else { months },
                seconds: 0.0,
            });
        }
        let mut left = self;
        let mut right = other;
        if least == 2 {
            left.hour = None;
            left.minute = None;
            left.second = None;
            left.kind = DateKind::Date;
            right.hour = None;
            right.minute = None;
            right.second = None;
            right.kind = DateKind::Date;
        }
        let seconds = right.unix_seconds()? - left.unix_seconds()?;
        if !seconds.is_finite() {
            return None;
        }
        Some(DurationValue::from_seconds(seconds))
    }
    fn add(mut self, duration: DurationValue) -> Option<Self> {
        if !DateKind::YEAR_BEARING.contains(&self.kind) {
            return None;
        }
        let original_kind = self.kind;
        let original_year = self.year?;
        if duration.months != 0 {
            let year = self.year?;
            let month = i64::from(self.month.unwrap_or(1));
            let serial = astronomical_year(year)
                .checked_mul(12)?
                .checked_add(month - 1)?
                .checked_add(duration.months)?;
            let astro = serial.div_euclid(12);
            self.year = Some(schema_year(astro));
            self.month = self.month.map(|_| (serial.rem_euclid(12) + 1) as u8);
            if let (Some(year), Some(month), Some(day)) = (self.year, self.month, self.day) {
                self.day = Some(day.min(days_in_month(year, month)));
            }
        }
        if duration.seconds != 0.0 {
            let base = self.clone().unix_seconds()? + duration.seconds;
            let timezone = f64::from(self.timezone.unwrap_or(0));
            let local = base + timezone;
            let days = (local / 86_400.0).floor() as i64;
            let mut seconds = local - days as f64 * 86_400.0;
            let (year, month, day) = civil_from_days(days + days_from_civil(1970, 1, 1));
            self.year = Some(year);
            self.month = Some(month);
            self.day = Some(day);
            self.hour = Some((seconds / 3600.0).floor() as u8);
            seconds %= 3600.0;
            self.minute = Some((seconds / 60.0).floor() as u8);
            self.second = Some(seconds % 60.0);
        }
        let has_time = self.hour.unwrap_or(0) != 0
            || self.minute.unwrap_or(0) != 0
            || self.second.unwrap_or(0.0) != 0.0;
        self.kind = match original_kind {
            DateKind::DateTime => DateKind::DateTime,
            DateKind::Date if has_time => DateKind::DateTime,
            DateKind::Date => DateKind::Date,
            DateKind::YearMonth if has_time => DateKind::DateTime,
            DateKind::YearMonth if self.day.unwrap_or(1) != 1 => DateKind::Date,
            DateKind::YearMonth => DateKind::YearMonth,
            DateKind::Year if has_time => DateKind::DateTime,
            DateKind::Year if self.day.unwrap_or(1) != 1 => DateKind::Date,
            DateKind::Year if self.month.unwrap_or(1) != 1 => DateKind::YearMonth,
            DateKind::Year => DateKind::Year,
            _ => return None,
        };
        if matches!(self.kind, DateKind::Date | DateKind::DateTime) {
            self.month.get_or_insert(1);
            self.day.get_or_insert(1);
        }
        if self.kind == DateKind::DateTime {
            self.hour.get_or_insert(0);
            self.minute.get_or_insert(0);
            self.second.get_or_insert(0.0);
        } else {
            self.hour = None;
            self.minute = None;
            self.second = None;
        }
        if self.timezone.is_none()
            && duration.seconds != 0.0
            && (original_kind == DateKind::Year || original_year.signum() != self.year?.signum())
        {
            // libexslt exposes its normalized UTC transition when arithmetic crosses
            // the XML Schema year-zero discontinuity.
            self.timezone = Some(0);
        }
        Some(self)
    }
    fn render(&self) -> String {
        let timezone = render_timezone(self.timezone);
        match self.kind {
            DateKind::Year => format!("{}{}", render_year(self.year.unwrap_or(1)), timezone),
            DateKind::YearMonth => format!(
                "{}-{:02}{}",
                render_year(self.year.unwrap_or(1)),
                self.month.unwrap_or(1),
                timezone
            ),
            DateKind::Date => format!(
                "{}-{:02}-{:02}{}",
                render_year(self.year.unwrap_or(1)),
                self.month.unwrap_or(1),
                self.day.unwrap_or(1),
                timezone
            ),
            DateKind::DateTime => format!(
                "{}-{:02}-{:02}T{}",
                render_year(self.year.unwrap_or(1)),
                self.month.unwrap_or(1),
                self.day.unwrap_or(1),
                self.time_string().unwrap_or_default()
            ),
            _ => String::new(),
        }
    }
}

fn split_timezone(input: &str) -> Option<(&str, Option<i32>)> {
    if let Some(body) = input.strip_suffix('Z') {
        return Some((body, Some(0)));
    }
    if input.len() >= 6 {
        let split = input.len() - 6;
        let suffix = &input[split..];
        if matches!(suffix.as_bytes()[0], b'+' | b'-') && suffix.as_bytes()[3] == b':' {
            let hours = suffix[1..3].parse::<i32>().ok()?;
            let minutes = suffix[4..6].parse::<i32>().ok()?;
            if hours > 14 || minutes > 59 || (hours == 14 && minutes != 0) {
                return None;
            }
            let sign = if suffix.starts_with('-') { -1 } else { 1 };
            return Some((&input[..split], Some(sign * (hours * 3600 + minutes * 60))));
        }
    }
    Some((input, None))
}

fn parse_year(input: &str) -> Option<(i64, &str)> {
    let negative = input.starts_with('-');
    let digits = input
        .strip_prefix('-')
        .unwrap_or(input)
        .chars()
        .take_while(char::is_ascii_digit)
        .count();
    if digits < 4 || (digits > 4 && input.trim_start_matches('-').starts_with('0')) {
        return None;
    }
    let consumed = digits + usize::from(negative);
    let value = input[..consumed].parse::<i64>().ok()?;
    (value != 0).then_some((value, &input[consumed..]))
}
fn parse_two(input: &str) -> Option<u8> {
    (input.len() == 2 && input.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| input.parse().ok())
        .flatten()
}
fn parse_time(input: &str) -> Option<(u8, u8, f64)> {
    let mut parts = input.split(':');
    let second_lexical = parts.next_back()?;
    let integer_digits = second_lexical
        .split_once('.')
        .map_or(second_lexical, |(integer, _)| integer);
    if integer_digits.len() != 2 || !integer_digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (hour, minute, second) = (
        parse_two(parts.next()?)?,
        parse_two(parts.next()?)?,
        second_lexical.parse::<f64>().ok()?,
    );
    (parts.next().is_none() && hour < 24 && minute < 60 && (0.0..60.0).contains(&second))
        .then_some((hour, minute, second))
}
fn is_leap(year: i64) -> bool {
    let year = astronomical_year(year);
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}
fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
fn valid_day(year: i64, month: u8, day: u8) -> bool {
    day >= 1 && day <= days_in_month(year, month)
}
fn ordinal(year: i64, month: u8, day: u8) -> u16 {
    (1..month)
        .map(|month| u16::from(days_in_month(year, month)))
        .sum::<u16>()
        + u16::from(day)
}
fn weekday(year: i64, month: u8, day: u8) -> u8 {
    (days_from_civil(year, month, day) + 3).rem_euclid(7) as u8
}
fn iso_week(year: i64, month: u8, day: u8) -> u8 {
    let ordinal = i32::from(ordinal(year, month, day));
    let monday = i32::from((weekday(year, month, day) + 6) % 7);
    let mut week = (ordinal - monday + 9) / 7;
    if week < 1 {
        week = i32::from(weeks_in_year(year - 1));
    } else if week > i32::from(weeks_in_year(year)) {
        week = 1;
    }
    week as u8
}
fn weeks_in_year(year: i64) -> u8 {
    if weekday(year, 1, 1) == 4 || (weekday(year, 1, 1) == 3 && is_leap(year)) {
        53
    } else {
        52
    }
}
fn astronomical_year(year: i64) -> i64 {
    if year < 0 { year + 1 } else { year }
}
fn schema_year(year: i64) -> i64 {
    if year <= 0 { year - 1 } else { year }
}
fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let mut y = astronomical_year(year);
    y -= i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from(month) + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy
}
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let era = days.div_euclid(146097);
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (schema_year(year), month as u8, day as u8)
}
fn month_name(month: u8) -> &'static str {
    [
        "",
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ][usize::from(month)]
}
fn day_name(day: u8) -> &'static str {
    [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ][usize::from(day)]
}
fn render_year(year: i64) -> String {
    if year < 0 {
        format!("-{:04}", year.unsigned_abs())
    } else {
        format!("{year:04}")
    }
}
fn render_timezone(timezone: Option<i32>) -> String {
    match timezone {
        Some(0) => "Z".into(),
        Some(seconds) => {
            let sign = if seconds < 0 { '-' } else { '+' };
            let minutes = seconds.unsigned_abs() / 60;
            format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60)
        }
        None => String::new(),
    }
}
fn format_second(second: f64) -> String {
    if second.fract() == 0.0 {
        format!("{:02}", second as u8)
    } else {
        let truncated = (second * 1_000_000_000.0).floor() / 1_000_000_000.0;
        let value = format!("{truncated:.9}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned();
        if second < 10.0 {
            format!("0{value}")
        } else {
            value
        }
    }
}
fn trim_float(value: f64) -> String {
    let rendered = format!("{value:.12}");
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}
fn argument_error<T>(message: &str) -> std::result::Result<T, function::Error> {
    Err(function::Error::Other {
        what: format!("EXSLT date function {message}"),
    })
}
