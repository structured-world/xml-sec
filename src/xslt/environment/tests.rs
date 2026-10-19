use super::{Clock, SystemClock};

#[test]
fn system_clock_remains_available_after_threads_start() {
    // Unix local-offset discovery may become indeterminate once the process is multithreaded;
    // compatibility mode must still provide an operation time.
    std::thread::spawn(|| SystemClock.now_local())
        .join()
        .expect("clock thread does not panic")
        .expect("system clock falls back to UTC when local offset is unavailable");
}
