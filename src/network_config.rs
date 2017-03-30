//! Module containing all functions and structures relating to the network configuration.

extern crate serde_json;
extern crate error_chain;
extern crate base64;

use std::io;
use std::result::Result as stdResult;
use std::net::{IpAddr, Ipv4Addr};
use std::io::prelude::*;
use std::str::FromStr;
use rand::{self, Rng};
use serde::{Serializer, Serialize, Deserialize, Deserializer};
use crypto::ed25519;

mod errors {
    error_chain!{}
}

use errors::*;

/// The internal representation of a network configuration.
#[derive(Debug, Serialize)]
pub struct NetworkConfig {
    /// Name of the network.
    ///
    /// This can be anything arbitrary, however if a node knows two of the same network name,
    /// one of them might be appended with a number.
    pub name: String,

    /// Network key associated with this network.
    pub key: NetworkKey,

    /// Network address of the network's subnet.
    pub network_addr: IpAddr,

    /// Size of the network mask in CIDR representation.
    pub cidr: u8,
}

/// A network key is used to connect to or control a network.
#[derive(Debug)]
pub struct NetworkKey {
    /// The access key allows you to access the network.
    pub access_key: Vec<u8>,
    /// The secret key allows you to control the network.
    pub secret_key: Option<Vec<u8>>,
}

impl NetworkConfig {
    /// Convert a NetworkConfig to JSON format, to be saved as a config file.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self).chain_err(|| "Could not serialize network config")
    }
}

impl ToString for NetworkKey {
    fn to_string(&self) -> String {
        let access_key_base64 = base64::encode_config(&self.access_key, base64::URL_SAFE_NO_PAD);
        match self.secret_key {
            Some(ref sec_key) => {
                let secret_key_base64 = base64::encode_config(&sec_key[..], base64::URL_SAFE_NO_PAD);
                {
                    let mut mut_output_str = String::with_capacity(access_key_base64.len() + secret_key_base64.len() + 1);
                    mut_output_str.push_str(&access_key_base64);
                    mut_output_str.push(':');
                    mut_output_str.push_str(&secret_key_base64);
                    mut_output_str
                }
            }
            _ => access_key_base64
        }
    }
}

impl FromStr for NetworkKey {
    type Err = Error;
    fn from_str(s: &str) -> stdResult<Self, Self::Err> {
        let mut keys = s.split(':')
            .flat_map(|key| base64::decode_config(key, base64::URL_SAFE_NO_PAD));
        if let Some(access_key) = keys.next() {
            Ok(NetworkKey {
                access_key: access_key,
                secret_key: keys.next()
            })
        } else {
            Err("Failed to deserialize access key".into())
        }
    }
}

impl Serialize for NetworkKey {
    /// Serialize a NetworkKey into a colon-separated string.
    ///
    /// If the network key contains a secret key, the output format will look like
    ///
    ///     <access_key>:<secret_key>
    ///
    /// If the network key does not contain a secret key, however, only the access
    /// key will be returned.
    fn serialize<S>(&self, serializer: S) -> stdResult<S::Ok, S::Error>
        where S: Serializer
    {
        let access_key_base64 = base64::encode_config(&self.access_key, base64::URL_SAFE_NO_PAD);
        match self.secret_key {
            Some(ref sec_key) => {
                let secret_key_base64 = base64::encode_config(&sec_key[..], base64::URL_SAFE_NO_PAD);
                let output_str = {
                    let mut mut_output_str = String::with_capacity(access_key_base64.len() + secret_key_base64.len() + 1);
                    mut_output_str.push_str(&access_key_base64);
                    mut_output_str.push(':');
                    mut_output_str.push_str(&secret_key_base64);
                    mut_output_str
                };
                serializer.serialize_str(&output_str)
            }
            _ => serializer.serialize_str(&access_key_base64),
        }

    }
}

impl Deserialize for NetworkKey {
    /// Deserialize a colon-separated string into a NetworkKey.
    fn deserialize<D>(deserializer: D) -> stdResult<Self, D::Error>
        where D: Deserializer
    {
        use serde::de::Error;

        String::deserialize(deserializer).and_then(|string| {
            let mut keys = string.split(':').flat_map(|key| base64::decode_config(key, base64::URL_SAFE_NO_PAD));
            if let Some(access_key) = keys.next() {
                Ok(NetworkKey {
                       access_key: access_key,
                       secret_key: keys.next(),
                   })
            } else {
                Err(Error::custom("Failed to deserialize access key"))
            }
        })
    }
}

/// Generate an access and secret key pair.
fn generate_secret_key() -> NetworkKey {
    let mut rng = rand::thread_rng();

    let mut seed: [u8; 32] = [0; 32];

    rng.fill_bytes(&mut seed);

    let (secret_key, access_key) = ed25519::keypair(&seed);

    NetworkKey {
        access_key: access_key.to_vec(),
        secret_key: Some(secret_key.to_vec()),
    }
}

/// Convert a string to an IP/CIDR pair.
///
/// Returns a Result for input errors, and an Option for empty input.
/// The option can be used to set a default subnet if one is not provided.
pub fn string_to_ip_cidr(input: &str) -> Result<Option<(IpAddr, u8)>> {
    if input.is_empty() {
        Ok(None)
    } else {
        let mut input_parts = input.split('/');

        let ip_addr_string = input_parts.next().ok_or("IP address not provided")?;
        let ip_addr: IpAddr = ip_addr_string.parse().chain_err(|| "Could not parse IP address")?;

        let cidr_string = input_parts.next().ok_or("CIDR not provided")?;
        let cidr: u8 = cidr_string.parse().chain_err(|| "Could not parse CIDR")?;
        if cidr > 30 {
            bail!("Invalid CIDR subnet")
        }

        Ok(Some((ip_addr, cidr)))
    }
}

/// Simple prompt function used by [new_network_prompt](fn.new_network_prompt.html).
pub fn question_prompt(input: &str) -> Result<String> {
    let mut stdout = io::stdout();

    write!(&mut stdout, "\n{}\n> ", input).chain_err(|| "Unable to write to stdout")?;
    stdout.flush().chain_err(|| "Unable to flush stdout")?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).chain_err(|| "Unable to read from stdin")?;
    Ok(input.trim().into())
}

/// Prompt for the information needed to generate a network config.
pub fn new_network_prompt() -> Result<NetworkConfig> {
    println!("To set up your network, we need to ask a few questions first.");

    let name = question_prompt("What should this network be called?")?;
    if name.is_empty() {
        bail!("A network name needs to be provided.");
    }

    let ip_cidr = question_prompt("What subnet should be used for this network? (or leave blank for 192.168.251.0/24)")?;

    let (ip_addr, cidr) = string_to_ip_cidr(&ip_cidr)?.unwrap_or((IpAddr::V4(Ipv4Addr::new(192, 168, 251, 0)), 24));

    let network_key = generate_secret_key();

    Ok(NetworkConfig {
           name: name,
           network_addr: ip_addr,
           key: network_key,
           cidr: cidr,
       })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_network_key() {
        let access_input = NetworkKey{ access_key: vec![105, 199, 44], secret_key: None };
        assert!(access_input.to_string() == "accs");

        let secret_input = NetworkKey{ access_key: vec![105, 199, 44], secret_key: Some(vec![177, 202, 237]) };
        assert!(secret_input.to_string() == "accs:scrt");
    }

    #[test]
    fn deserialize_network_key() {

    }

    #[test]
    fn blah_deserialize() {

    }

}
