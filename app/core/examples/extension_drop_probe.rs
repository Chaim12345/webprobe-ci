//! Loopback proof for the extension-drop parity fix. Run with:
//! cargo run -p webprobe-core --example extension_drop_probe
//! Then: curl --noproxy '' -i -x http://127.0.0.1:18081 http://127.0.0.1:18765/admin-drop
//! No destination server is needed: a dropped request must never connect to it.
use std::net::TcpListener;
use webprobe_core::{ext_host, net};

struct DropRequest;
impl ext_host::ProxyHooks for DropRequest {
    fn extension_name(&self) -> &str {
        "Loopback drop probe"
    }
    fn handle_request_received(
        &self,
        _: &ext_host::HttpService,
        _: &str,
        _: &str,
        _: &mut Vec<u8>,
    ) -> ext_host::ProxyAction {
        ext_host::ProxyAction::Drop
    }
}

fn main() {
    let shared = net::Shared::new();
    ext_host::with_host(&shared, |host| {
        host.extensions
            .push(ext_host::LoadedExtension::new(DropRequest));
    });
    let listener = TcpListener::bind("127.0.0.1:18081").unwrap();
    println!("Drop probe listening on 127.0.0.1:18081 for one request");
    let (stream, _) = listener.accept().unwrap();
    net::handle_conn(shared, stream);
}
