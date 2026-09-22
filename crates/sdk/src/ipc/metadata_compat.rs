use super::*;

#[test]
fn file_metadata_requires_ipc21_and_preserves_existing_file_wire_tags() {
    use crate::sharing::{Metadata, Reply, Request as Files};
    let inspect = Request::Sharing(Files::Inspect { id: [7; 16] });
    assert_eq!(inspect.minimum_version(), 21);
    assert_eq!(
        Request::Sharing(Files::CommitReusing { id: [7; 16] }).minimum_version(),
        20
    );
    assert_eq!(
        postcard::to_allocvec(&Files::CommitReusing { id: [7; 16] }).unwrap(),
        [&[11][..], &[7; 16]].concat()
    );
    assert_eq!(
        postcard::to_allocvec(&Files::Inspect { id: [7; 16] }).unwrap(),
        [&[12][..], &[7; 16]].concat()
    );
    let metadata = Reply::Metadata(Metadata {
        id: [7; 16],
        name: "drone".into(),
        sha256: [8; 32],
        size_bytes: 1,
    });
    let wire = postcard::to_allocvec(&metadata).unwrap();
    assert_eq!(wire[0], 3);
    assert_eq!(postcard::from_bytes::<Reply>(&wire).unwrap(), metadata);
}
