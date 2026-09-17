#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Local bounded parsing only; no sockets, identities or deployed targets.
    if data.len() > 16384 { return; }
    if let Ok(cell) = gcoms_core::decode(data) {
        let bucket = gcoms_core::Bucket::from_len(data.len()).unwrap();
        assert_eq!(cell.encode(bucket).unwrap(), data);
    }
});
