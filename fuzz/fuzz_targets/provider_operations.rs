#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| xml_sec_fuzz::provider_operations(data));
