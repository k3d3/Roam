#![recursion_limit = "1024"]

#[macro_use] extern crate serde_derive;
#[macro_use]
extern crate error_chain;
extern crate clap;

mod network_config;

use clap::{App, Arg, SubCommand, AppSettings};

mod errors {
    error_chain!{}
}

fn main() {
    let matches = App::new("Roam")
        .version("0.1")
        .about("Direct P2P VPN")
        .arg(Arg::with_name("ncurses")
                 .short("n")
                 .long("ncurses")
                 .help("Show an ncurses interface"))
        .subcommand(SubCommand::with_name("new").about("Create a new network"))
        .subcommand(SubCommand::with_name("connect").about("Connect to an existing network"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::ColoredHelp)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::DisableHelpSubcommand)
        .setting(AppSettings::InferSubcommands)
        .get_matches();

    match matches.subcommand_name() {
        Some("new") => {
            match network_config::new_network_prompt() {
                Ok(network) => {
                    println!("Network is {:?}", network);
                    network_config::save_network_config(network);
                }
                Err(err) => {
                    println!("Error: {}", err);
                    for e in err.iter().skip(1) {
                        println!("Caused by: {}", e);
                    }
                }
            }
        }
        Some("connect") => {
            println!("Connect!");
        }
        _ => {}
    }
}

