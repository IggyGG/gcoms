#[test]
fn rejects_nonportable_and_ambiguous_contracts() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
