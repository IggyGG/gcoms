use gcoms_core::{decode, Bucket};

#[test]
fn independent_raw_cell_vectors() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/cells.json")).unwrap();
    for fixture in fixtures["vectors"].as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let raw = hex::decode(fixture["hex"].as_str().unwrap()).unwrap();
        let result = decode(&raw);
        if fixture["valid"] == false {
            assert!(result.is_err(), "{name}");
            continue;
        }
        let cell = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            cell.raw_type,
            fixture["type"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            cell.flags,
            fixture["flags"].as_u64().unwrap() as u8,
            "{name}"
        );
        assert_eq!(
            cell.round_ctr,
            fixture["round"].as_u64().unwrap() as u16,
            "{name}"
        );
        assert_eq!(
            hex::encode(&cell.payload),
            fixture["payload_hex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            cell.encode(Bucket::from_len(raw.len()).unwrap()).unwrap(),
            raw,
            "{name}"
        );
    }
}

#[test]
fn historical_identity_binding_domain_is_unchanged() {
    // Literal fixed bytes from the pre-extraction signature domain and role tag.
    let expected = hex::decode(concat!(
        "67686f73742e7072696e636970616c2d62696e64696e672e7369676e61747572652e76310003",
        "abababababababababababababababababababababababababababababababab"
    ))
    .unwrap();
    assert_eq!(
        gcoms_core::principal_binding_signature_payload(&[0xab; 32]),
        expected
    );
}
