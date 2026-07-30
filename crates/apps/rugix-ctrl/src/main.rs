//! Rugix Ctrl device lifecycle management application.
//!
//! The binary runs early-boot initialization when invoked as the init process
//! and otherwise dispatches the Rugix Ctrl command-line interface.

pub mod apps;
pub mod boot;
pub mod cli;
pub mod components;
pub mod config;
pub mod daemon;
pub mod http;
pub mod http_source;
pub mod init;
pub mod operations;
pub mod overlay;
pub mod payload_db;
pub mod state;
pub mod system;
pub mod system_state;
pub mod utils;

pub fn main() {
    http::setup();
    let result = rugix_tasks::run(|| {
        if utils::is_init_process() {
            init::main()
        } else {
            cli::main()
        }
    });
    if let Err(report) = result {
        eprintln!("{report:?}");
        std::process::exit(1);
    }
}

mod component_format;
