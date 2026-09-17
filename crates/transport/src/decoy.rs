use bytes::Bytes;
use http::Response;

pub const DECOY_HTML: &str = "<!DOCTYPE html>\n<html><head><title>Device</title></head><body><h1>Device console</h1><p>Local service.</p></body></html>\n";

pub fn decoy_response(status: u16) -> Response<()> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "max-age=3600")
        .body(())
        .expect("static decoy response builds")
}

pub fn decoy_body(status: u16) -> Bytes {
    if status == 200 {
        Bytes::from(DECOY_HTML)
    } else {
        Bytes::from("<html><body><h1>Not found</h1></body></html>\n")
    }
}
