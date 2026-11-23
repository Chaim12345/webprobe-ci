//! WebProbe engine: proxy, scanner, Intruder, session handling, project
//! files and the other tools, with no user interface. The desktop app
//! (`webprobe`) is one front end on top of it; a headless runner or an API
//! server can be another.

pub mod ai;
pub mod bambda;
pub mod bambda_library;
pub mod burp_checks;
pub mod codec;
pub mod collaborator;
pub mod cookie_jar;
pub mod crawl;
pub mod ext_calls;
pub mod ext_host;
pub mod ext_process;
pub mod ext_store;
pub mod h2;
pub mod h2_server;
#[cfg(test)]
mod h2_server_tests;
pub mod headless;
pub mod history;
pub mod inspector;
pub mod interactsh;
#[cfg(test)]
mod intercept_release_tests;
pub mod intruder;
pub mod intruder_run;
#[cfg(test)]
mod jwt_tests;
pub mod strict_chunked;
pub mod strict_request;
// Stage A (#37): acyclic leaf modules extracted to the webprobe-support crate.
// Re-exported so `webprobe_core::<module>` paths are unchanged.
pub use webprobe_support::{
    analysis, body, compare, decoder_ops, hash_list, intercept_rules, jwt, logger, mime, notice,
    organizer, paths, rules, seq_bits, streaming, sync, tls, util, variations, xss,
};

pub mod macros;
pub mod net;
pub mod oob;
pub mod passive_state;
pub mod project;
pub mod project_files;
pub mod repeater_run;
#[cfg(test)]
mod request_reader_tests;
pub mod rt;
pub mod scan;
pub mod scan_config;
pub mod scan_library;
pub mod scan_run;
pub mod setup_page;
pub mod sitemap_compare;
pub mod stored;
#[cfg(test)]
mod streaming_tests;
pub mod tasks;
pub mod upstream;
mod util_tests;
pub mod ws_history;
pub mod ws_repeater;
#[cfg(test)]
mod ws_repeater_tests;
pub mod ws_rules;
#[cfg(test)]
mod ws_tests;

#[cfg(test)]
mod framing_fixtures_tests;
#[cfg(test)]
mod framing_keepalive_tests;
#[cfg(test)]
mod fuzz_tests;
#[cfg(test)]
mod parser_fuzz_tests;
#[cfg(test)]
mod strict_chunked_tests;
#[cfg(test)]
mod strict_request_tests;
