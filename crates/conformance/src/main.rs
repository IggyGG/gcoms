fn main() {
    if std::env::args().nth(1).as_deref() == Some("--emit") {
        for (name, value) in gcoms_conformance::computed().expect("compute conformance vectors") {
            println!("{name}={value}");
        }
        return;
    }

    let count =
        gcoms_conformance::verify(gcoms_conformance::VECTORS).expect("GC/1 conformance failed");
    println!("GC/1 conformance v1: {count} vectors passed");
}
