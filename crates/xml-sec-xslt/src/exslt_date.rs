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
    ("date-time", Operation::DateTime),
    ("date", Operation::Date),
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
    DateTime,
    Date,
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
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> std::result::Result<Value<'d>, function::Error> {
        use Operation::*;
        match self.0 {
            DateTime if !args.is_empty() => {
                return argument_error("date:date-time() requires no arguments");
            }
            AddDuration | Add | Difference if args.len() != 2 => {
                return argument_error("requires two arguments");
            }
            Sum if args.len() != 1 => return argument_error("requires one argument"),
            AddDuration | Add | Difference | Sum => {}
            _ if args.len() > 1 => return argument_error("requires zero or one argument"),
            _ => {}
        }
        match self.0 {
            DateTime => Ok(Value::String(current_datetime_for_operation(
                self.1.as_ref(),
                self.2,
            )?)),
            Date => {
                let current;
                let input = if let Some(input) = args.first().map(Value::string) {
                    current = input;
                    current.as_str()
                } else {
                    current = current_datetime_for_operation(self.1.as_ref(), self.2)?;
                    current.as_str()
                };
                let Some(mut date) = DateValue::parse(input) else {
                    return Ok(Value::String(String::new()));
                };
                if !DateKind::COMPLETE_DATE.contains(&date.kind) {
                    return Ok(Value::String(String::new()));
                }
                date.kind = DateKind::Date;
                Ok(Value::String(date.render()))
            }
            Sum => {
                let Value::Nodeset(nodes) = &args[0] else {
                    return argument_error("date:sum() requires a node-set");
                };
                if nodes.size() == 0 {
                    return Ok(Value::String(String::new()));
                }
                let mut total = DurationValue::default();
                for node in nodes.document_order_with_context(context)? {
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
            Duration => {
                // EXSLT date:duration defaults an omitted argument to zero-argument
                // date:seconds(), including its controlled operation-clock semantics.
                // https://exslt.github.io/date/functions/duration/date.duration.html
                let seconds = if let Some(value) = args.first() {
                    value.number(context)?
                } else {
                    current_seconds_for_operation(self.1.as_ref(), self.2)?
                };
                let duration = DurationValue::from_seconds(seconds).render();
                Ok(Value::String(duration))
            }
            Seconds => {
                // Omitted date:seconds input defaults to date:date-time, so it shares the same
                // controlled clock and deterministic-policy gate.
                // https://exslt.github.io/date/functions/seconds/date.seconds.html
                let Some(input) = args.first().map(Value::string) else {
                    return Ok(Value::Number(current_seconds_for_operation(
                        self.1.as_ref(),
                        self.2,
                    )?));
                };
                let seconds = DurationValue::parse_libxslt_seconds(&input)
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
                    current = current_datetime_for_operation(self.1.as_ref(), self.2)?;
                    &current
                };
                evaluate_component(operation, Some(input))
            }
        }
    }
}

fn current_datetime_for_operation(
    clock: &dyn Clock,
    extension_policy: ExtensionPolicy,
) -> std::result::Result<String, function::Error> {
    Ok(render_current_datetime(current_time_for_operation(
        clock,
        extension_policy,
    )?))
}

fn current_seconds_for_operation(
    clock: &dyn Clock,
    extension_policy: ExtensionPolicy,
) -> std::result::Result<f64, function::Error> {
    Ok(current_time_for_operation(clock, extension_policy)?.unix_timestamp() as f64)
}

fn current_time_for_operation(
    clock: &dyn Clock,
    extension_policy: ExtensionPolicy,
) -> std::result::Result<time::OffsetDateTime, function::Error> {
    if extension_policy == ExtensionPolicy::Deterministic {
        return argument_error(
            "zero-argument EXSLT date functions are disabled by the execution extension policy",
        );
    }
    let current = clock.now_local().map_err(|error| function::Error::Other {
        what: error.to_string(),
    })?;
    let offset_seconds = current.offset().whole_seconds();
    // XML Schema 1.0 Part 2 section 3.2.7.3 permits minute-aligned offsets only through +/-14:00.
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones
    if offset_seconds % 60 != 0 || offset_seconds.unsigned_abs() > 14 * 60 * 60 {
        let message = format!(
            "clock timezone offset {} seconds is not representable by XML Schema dateTime",
            offset_seconds
        );
        return argument_error(&message);
    }
    Ok(current)
}

fn render_current_datetime(current: time::OffsetDateTime) -> String {
    // EXSLT date:date-time uses XSD 1.0 §3.2.7, whose Appendix D.3.2 forbids year zero:
    // https://www.w3.org/TR/xmlschema-2/#noYearZero
    let year = render_year(schema_year(i64::from(current.year())));
    let offset = current.offset().whole_seconds();
    let sign = if offset < 0 { '-' } else { '+' };
    let offset = offset.unsigned_abs();
    format!(
        "{year}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        u8::from(current.month()),
        current.day(),
        current.hour(),
        current.minute(),
        current.second(),
        offset / 3600,
        (offset % 3600) / 60,
    )
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

const MAX_RENDERABLE_DURATION_SECONDS: f64 = u64::MAX as f64 * 86_400.0;

impl DurationValue {
    fn parse(input: &str) -> Option<Self> {
        Self::parse_with_legacy_seconds(input, false)
    }

    fn parse_libxslt_seconds(input: &str) -> Option<Self> {
        // libxslt date:seconds() accepts a leading decimal point in the seconds component even
        // though XML Schema Part 2 section 3.2.6.1 requires a preceding numeral. Keep that
        // compatibility quirk local to this one oracle-facing conversion; duration arithmetic
        // remains schema-strict. https://www.w3.org/TR/xmlschema-2/#duration-lexical-representation
        Self::parse_with_legacy_seconds(input, true)
    }

    fn parse_with_legacy_seconds(input: &str, allow_legacy_seconds: bool) -> Option<Self> {
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
            let lexical_value = &rest[..end];
            let designator = rest[end..].chars().next()?;
            // XML Schema Part 2 section 3.2.6.1 requires the seconds numeral before an optional
            // decimal fraction; Rust's float parser additionally accepts the invalid `.5` form.
            // https://www.w3.org/TR/xmlschema-2/#duration-lexical-representation
            if lexical_value.starts_with('.') && !(allow_legacy_seconds && designator == 'S') {
                return None;
            }
            let value = lexical_value.parse::<f64>().ok()?;
            if !value.is_finite() {
                return None;
            }
            let rank = match (in_time, designator) {
                (false, 'Y') => 1,
                (false, 'M') => 2,
                (false, 'D') => 3,
                (true, 'H') => 4,
                (true, 'M') => 5,
                (true, 'S') => 6,
                _ => return None,
            };
            // XML Schema 1.0 erratum E2-23 requires a digit after the decimal point, but the
            // pinned libxslt compatibility oracle accepts a trailing point in seconds (`1.S`).
            // Preserve that deliberate oracle behavior while still rejecting decimals in every
            // other component.
            // https://www.w3.org/2001/05/xmlschema-errata#e2-23
            if rank <= last_rank || (rank != 6 && lexical_value.contains('.')) {
                return None;
            }
            match rank {
                1 | 2 => {
                    if value >= i64::MAX as f64 {
                        return None;
                    }
                    let months = (value as i64).checked_mul(if rank == 1 { 12 } else { 1 })?;
                    result.months = result.months.checked_add(months)?;
                }
                3..=6 => {
                    let scale = match rank {
                        3 => 86_400.0,
                        4 => 3_600.0,
                        5 => 60.0,
                        6 => 1.0,
                        _ => unreachable!(),
                    };
                    result.seconds += value * scale;
                    if !result.seconds.is_finite() {
                        return None;
                    }
                }
                _ => unreachable!(),
            }
            saw = true;
            last_rank = rank;
            rest = &rest[end + designator.len_utf8()..];
        }
        let months = if sign < 0.0 {
            result.months.checked_neg()?
        } else {
            result.months
        };
        let seconds = result.seconds * sign;
        (saw && seconds.is_finite()).then_some(Self { months, seconds })
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
        if !self.seconds.is_finite() || self.seconds.abs() >= MAX_RENDERABLE_DURATION_SECONDS {
            return String::new();
        }
        if self.months == 0 && self.seconds == 0.0 {
            return "P0D".into();
        }
        let negative = self.months < 0 || self.seconds < 0.0;
        let months = self.months.unsigned_abs();
        let mut seconds = self.seconds.abs();
        let rounded = seconds.round();
        if rounded != 0.0 && (seconds - rounded).abs() < 1e-9 {
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
            return ((1..=12).contains(&month) && valid_day(2000, month, day)).then_some(Self {
                month: Some(month),
                day: Some(day),
                kind: DateKind::MonthDay,
                ..empty
            });
        }
        if body.contains(':') && !body.contains('T') {
            let time = parse_time(body)?;
            return Some(Self {
                hour: Some(time.hour),
                minute: Some(time.minute),
                second: Some(time.second),
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
        let mut day = parse_two(day)?;
        if !valid_day(year, month, day) {
            return None;
        }
        if let Some(time) = time {
            let time = parse_time(time)?;
            let (mut year, mut month) = (year, month);
            if time.advances_day {
                // XML Schema Part 2 section 3.2.7.1 defines hour 24 with zero minutes and
                // seconds as the first instant of the following day.
                // https://www.w3.org/TR/xmlschema-2/#dateTime-lexical-representation
                (year, month, day) = civil_from_days(days_from_civil(year, month, day) + 1)?;
            }
            Some(Self {
                year: Some(year),
                month: Some(month),
                day: Some(day),
                hour: Some(time.hour),
                minute: Some(time.minute),
                second: Some(time.second),
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
        let seconds = days as f64 * 86_400.0 + time - f64::from(self.timezone.unwrap_or(0));
        seconds.is_finite().then_some(seconds)
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
            if least == 0 {
                // EXSLT date:difference first truncates both operands to their common precision;
                // subtracting serial months before truncation gives the wrong sign near a year.
                // https://exslt.github.io/date/functions/difference/date.difference.1.html
                let years =
                    astronomical_year(other.year?).checked_sub(astronomical_year(self.year?))?;
                return Some(DurationValue {
                    months: years.checked_mul(12)?,
                    seconds: 0.0,
                });
            }
            let serial_month = |date: &Self| {
                astronomical_year(date.year?)
                    .checked_mul(12)?
                    .checked_add(i64::from(date.month.unwrap_or(1)) - 1)
            };
            let months = serial_month(&other)?.checked_sub(serial_month(&self)?)?;
            return Some(DurationValue {
                months,
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
            // EXSLT date:add promotes gYear to gYearMonth before applying a non-zero month
            // component, so the computed month must survive even when the input omitted it.
            // https://exslt.github.io/date/functions/add/date.add.2.html
            self.month = Some((serial.rem_euclid(12) + 1) as u8);
            if let (Some(year), Some(month), Some(day)) = (self.year, self.month, self.day) {
                self.day = Some(day.min(days_in_month(year, month)));
            }
        }
        if duration.seconds != 0.0 {
            let base = self.clone().unix_seconds()? + duration.seconds;
            let timezone = f64::from(self.timezone.unwrap_or(0));
            let local = base + timezone;
            if !local.is_finite() {
                return None;
            }
            let days = (local / 86_400.0).floor();
            let minimum = days_from_civil(i64::MIN, 1, 1) as f64;
            let maximum = days_from_civil(i64::MAX, 12, 31) as f64;
            if days < minimum || days > maximum {
                return None;
            }
            let days = days as i128;
            let mut seconds = local - days as f64 * 86_400.0;
            let (year, month, day) = civil_from_days(days + days_from_civil(1970, 1, 1))?;
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
        let Some(suffix) = input.get(split..) else {
            return Some((input, None));
        };
        if matches!(suffix.as_bytes()[0], b'+' | b'-') && suffix.as_bytes()[3] == b':' {
            let hours = suffix[1..3].parse::<i32>().ok()?;
            let minutes = suffix[4..6].parse::<i32>().ok()?;
            if hours > 14 || minutes > 59 || (hours == 14 && minutes != 0) {
                return None;
            }
            let sign = if suffix.starts_with('-') { -1 } else { 1 };
            return Some((
                input.get(..split)?,
                Some(sign * (hours * 3600 + minutes * 60)),
            ));
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
struct ParsedTime {
    hour: u8,
    minute: u8,
    second: f64,
    advances_day: bool,
}

fn parse_time(input: &str) -> Option<ParsedTime> {
    let mut parts = input.split(':');
    let second_lexical = parts.next_back()?;
    let integer_digits = match second_lexical.split_once('.') {
        Some((integer, fraction))
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            integer
        }
        Some(_) => return None,
        None => second_lexical,
    };
    if integer_digits.len() != 2 || !integer_digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (hour, minute, second) = (
        parse_two(parts.next()?)?,
        parse_two(parts.next()?)?,
        second_lexical.parse::<f64>().ok()?,
    );
    if parts.next().is_some() || minute >= 60 || !(0.0..60.0).contains(&second) {
        return None;
    }
    if hour < 24 {
        return Some(ParsedTime {
            hour,
            minute,
            second,
            advances_day: false,
        });
    }
    // XML Schema Part 2 sections 3.2.7.1 and 3.2.8.1 permit only the lexical
    // end-of-day form 24:00:00(.0+); inspect digits rather than a rounded float.
    // https://www.w3.org/TR/xmlschema-2/#time-lexical-representation
    let end_second = second_lexical == "00"
        || second_lexical.strip_prefix("00.").is_some_and(|fraction| {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte == b'0')
        });
    (hour == 24 && minute == 0 && end_second).then_some(ParsedTime {
        hour: 0,
        minute: 0,
        second: 0.0,
        advances_day: true,
    })
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
        week = i32::from(weeks_in_astronomical_year(
            i128::from(astronomical_year(year)) - 1,
        ));
    } else if week > i32::from(weeks_in_year(year)) {
        week = 1;
    }
    week as u8
}
fn weeks_in_year(year: i64) -> u8 {
    weeks_in_astronomical_year(i128::from(astronomical_year(year)))
}
fn weeks_in_astronomical_year(year: i128) -> u8 {
    let weekday = (days_from_civil_i128(year, 1, 1) + 3).rem_euclid(7) as u8;
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    if weekday == 4 || (weekday == 3 && leap) {
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
fn days_from_civil(year: i64, month: u8, day: u8) -> i128 {
    days_from_civil_i128(i128::from(astronomical_year(year)), month, day)
}
fn days_from_civil_i128(mut y: i128, month: u8, day: u8) -> i128 {
    y -= i128::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i128::from(month) + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + i128::from(day) - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy
}
fn civil_from_days(days: i128) -> Option<(i64, u8, u8)> {
    let era = days.div_euclid(146097);
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i128::from(month <= 2);
    let year = if year <= 0 {
        year.checked_sub(1)?
    } else {
        year
    };
    Some((year.try_into().ok()?, month as u8, day as u8))
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
    const DISPLAY_SCALE: f64 = 1_000_000_000_000.0;
    let rendered = if value.abs() >= DISPLAY_SCALE.recip() {
        (value * DISPLAY_SCALE).round() / DISPLAY_SCALE
    } else {
        value
    };
    crate::value::format_xpath_number(rendered)
}
fn argument_error<T>(message: &str) -> std::result::Result<T, function::Error> {
    Err(function::Error::Other {
        what: format!("EXSLT date function {message}"),
    })
}

#[cfg(test)]
mod tests {
    use super::{DateValue, DurationValue, split_timezone};

    #[test]
    fn end_of_day_lexical_forms_normalize_without_accepting_later_times() {
        // End-of-day advances a dateTime but is the same midnight value for standalone time;
        // no non-zero minute or second spelling may enter that normalization path.
        assert_eq!(
            DateValue::parse("2000-12-31T24:00:00Z")
                .expect("XML Schema end-of-day form parses")
                .render(),
            "2001-01-01T00:00:00Z"
        );
        assert_eq!(
            DateValue::parse("24:00:00.000+02:00")
                .expect("standalone end-of-day time parses")
                .time_string()
                .as_deref(),
            Some("00:00:00+02:00")
        );
        for invalid in [
            "24:00:00.1",
            "24:00:00.0000000000000000000000001",
            "24:00:01",
            "24:01:00",
            "12:34:56.",
            "2000-01-01T12:34:56.",
        ] {
            assert!(DateValue::parse(invalid).is_none(), "accepted {invalid}");
        }
    }

    #[test]
    fn month_day_rejects_out_of_range_months() {
        assert!(DateValue::parse("--50-15").is_none());
        assert!(DateValue::parse("--02-29").is_some());
    }

    #[test]
    fn timezone_probe_never_slices_inside_utf8() {
        assert_eq!(split_timezone("é12345"), Some(("é12345", None)));
    }

    #[test]
    fn extreme_duration_and_date_arithmetic_fail_closed() {
        assert!(DurationValue::parse("P999999999999999999999Y").is_none());
        let maximum =
            DateValue::parse("9223372036854775807-12-31").expect("maximum schema year parses");
        assert!(maximum.add(DurationValue::from_seconds(86_400.0)).is_none());
    }

    #[test]
    fn duration_seconds_require_an_integer_part() {
        // XML Schema Part 2 section 3.2.6.1 requires the seconds numeral before an optional
        // decimal fraction: https://www.w3.org/TR/xmlschema-2/#duration-lexical-representation
        assert!(DurationValue::parse("PT.5S").is_none());
    }

    #[test]
    fn duration_render_preserves_nonzero_subnanosecond_values() {
        for lexical in ["PT0.0000000001S", "PT0.0000000000001S"] {
            let duration = DurationValue::parse(lexical).expect("valid duration parses");
            assert_ne!(duration.render(), "P");
            assert_eq!(duration.render(), lexical);
        }
    }

    #[test]
    fn duration_render_rejects_unrepresentable_finite_seconds() {
        // Every operation funnels through render, so arithmetic cannot saturate a float-to-int
        // conversion into a plausible but incorrect duration.
        assert_eq!(DurationValue::from_seconds(1.0e30).render(), "");
        assert_eq!(DurationValue::from_seconds(-1.0e30).render(), "");
    }
}
