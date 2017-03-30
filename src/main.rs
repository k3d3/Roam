//! Roam is a simple, secure peer-to-peer VPN.
//!
//! Unlike a tool such as OpenVPN, Roam connects directly to each endpoint, rather than going
//! through a central server.
//!
//! Every network is identified by a randomly generated shared secret, such as
//!
//! ```text
//! ml0Pm4ie8ZL81DdFmft5x2rNfy2Xgl534CKs1ObBb-0
//! ```
//!
//! This secret is actually the public side of a cryptographic key pair. With the secret key, a key
//! pair looks like
//!
//! ```text
//! ml0Pm4ie8ZL81DdFmft5x2rNfy2Xgl534CKs1ObBb-0:T4SW7Ap-VIBUzjgtLkis4WKIE3M2Ozd4m0PGbWkqdIeaXQ-biJ7xkvzUN0WZ-3nHas1_LZeCXnfgIqzU5sFv7Q
//! ```
//!
//! This secret key gives you full control over the network, giving you the ability to change the
//! general configuration, whitelist/blacklist/kick nodes, etc.
//!
//! If you only have the access key, however, you can only connect to the network.

#![recursion_limit = "1024"]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate error_chain;
extern crate clap;
extern crate serde;
extern crate rand;
extern crate crypto;

mod network_config;

use clap::{App, Arg, SubCommand, AppSettings};

mod errors {
    error_chain!{}
}

/// Entry point into Roam. Basically just a Clap interface that calls one of the `command_*` functions.
fn main() {
    let matches = App::new("Roam")
        .version("0.1")
        .about("Simple, secure P2P VPN")
        .arg(Arg::with_name("ncurses").short("n").long("ncurses").help("Show an ncurses interface"))
        .subcommand(SubCommand::with_name("new").about("Create a new network"))
        .subcommand(SubCommand::with_name("connect").about("Connect to an existing network"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::DisableHelpSubcommand)
        .setting(AppSettings::InferSubcommands)
        .get_matches();

    match matches.subcommand_name() {
        Some("new") => command_new(),
        Some("connect") => command_connect(),
        Some("monitor") => command_monitor(),
        _ => {}
    }
}

/// Command to build a new network.
fn command_new() {
    match network_config::new_network_prompt() {
        Ok(network) => {
            println!("Network is {:?}", network);
            //network_config::save_network_config(&network);
        }
        Err(err) => {
            println!("Error: {}", err);
            for e in err.iter().skip(1) {
                println!("Caused by: {}", e);
            }
        }
    }
}

/// Command to connect to an existing network.
fn command_connect() {

}

/// Command to run an ncurses monitor a connected network.
fn command_monitor() {

}