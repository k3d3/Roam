extern crate serde;
extern crate serde_json;
extern crate error_chain;
extern crate rand;
extern crate base64;
extern crate crypto;

use std::io;
use std::result::Result as stdResult;
use std::net::{IpAddr, Ipv4Addr};
use std::io::prelude::*;
use network_config::rand::Rng;
use self::serde::{Serialize, Serializer, Deserialize, Deserializer};
use self::crypto::ed25519;

mod errors {
    error_chain!{}
}

use errors::*;

// A network key is an ed25519-derived keypair.
// Knowledge of the public key allows you to join the network
// Knowledge of the access key allows you to control/config the network
#[derive(Debug)]
pub struct NetworkKey {
    pub access_key: Vec<u8>,
    pub secret_key: Option<Vec<u8>>
}

impl Serialize for NetworkKey {
    fn serialize<S>(&self, serializer: S) -> stdResult<S::Ok, S::Error> 
        where S: Serializer
    {
        let access_key_base64 = base64::encode_config(&self.access_key, base64::URL_SAFE_NO_PAD);
        if let Some(ref sec_key) = self.secret_key {
            let secret_key_base64 = base64::encode_config(&sec_key[..], base64::URL_SAFE_NO_PAD);
            let output_str = {
                let mut mut_output_str = String::with_capacity(access_key_base64.len() + secret_key_base64.len() + 1);
                mut_output_str.push_str(&access_key_base64);
                mut_output_str.push(':');
                mut_output_str.push_str(&secret_key_base64);
                mut_output_str
            };
            serializer.serialize_str(&output_str)
        } else {
            serializer.serialize_str(&access_key_base64)
        }
    }
}

impl Deserialize for NetworkKey {
    fn deserialize<D>(deserializer: D) -> stdResult<Self, D::Error>
        where D: Deserializer
    {
        use self::serde::de::Error;

        String::deserialize(deserializer)
            .and_then(|string| {
                let mut keys = string.split(":")
                .flat_map(|key| base64::decode_config(key, base64::URL_SAFE_NO_PAD));
                if let Some(access_key) = keys.next() {
                    Ok(NetworkKey{ access_key: access_key, secret_key: keys.next() })
                } else {
                    Err(Error::custom("Failed to deserialize access key"))
                }
            })
    }
}

/*fn as_base64<S>(key: &PublicKey, serializer: &mut S) -> Result<(), S::Error>
    where S: Serializer
{
    serializer.serialize_str(&base64::encode(&key[..]))
}

fn from_base64<D>(deserializer: &mut D) -> Result<PublicKey, D::Error>
    where D: Deserializer
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
        .map(|bytes| PublicKey::from_slice(&bytes))
        .and_then(|opt| opt.ok_or_else(|| Error::custom("failed to deserialize public key")))
}*/

#[derive(Debug, Serialize)]
pub struct NetworkConfig {
    pub name: String,
    pub key: NetworkKey,
    pub network_addr: IpAddr,
    pub cidr: u8
}

fn generate_secret_key() -> NetworkKey {
    let mut rng = rand::thread_rng();

    let mut seed: [u8; 32] = [0; 32];

    rng.fill_bytes(&mut seed);
    
    let (secret_key, access_key) = ed25519::keypair(&seed);
    
    NetworkKey { access_key: access_key.to_vec(), secret_key: Some(secret_key.to_vec()) }
}

fn string_to_ip_cidr(input: &str) -> Result<Option<(IpAddr, u8)>> {
    if input.is_empty() {
        Ok(None)
    } else {
        let mut input_parts = input.split("/");

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

fn question_prompt(input: &str) -> Result<String> {
    let mut stdout = io::stdout();

    write!(&mut stdout, "\n{}\n> ", input).chain_err(|| "Unable to write to stdout")?;
    stdout.flush().chain_err(|| "Unable to flush stdout")?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).chain_err(|| "Unable to read from stdin")?;
    Ok(input.trim().into())
}

pub fn new_network_prompt() -> Result<NetworkConfig> {
    println!("To set up your network, we need to ask a few questions first.");

    let name = question_prompt("What should this network be called?")?;
    if name.is_empty() {
        bail!("A network name needs to be provided.");
    }

    let (ip_addr, cidr) = string_to_ip_cidr(
        &question_prompt("What subnet should be used for this network? (or leave blank for 192.168.251.0/24)")?
    )?.unwrap_or((IpAddr::V4(Ipv4Addr::new(192, 168, 251, 0)), 24));

    let network_key = generate_secret_key();

    Ok(NetworkConfig {
           name: name,
           network_addr: ip_addr,
           key: network_key,
           cidr: cidr
       })
}

pub fn save_network_config(config: NetworkConfig) -> Result<()> {
    let config_json =
        serde_json::to_string_pretty(&config).chain_err(|| "Could not save network config")?;
    println!("config json: {}", config_json);
    Ok(())
}

mod test {
    use super::*;

    #[test]
    fn test_generate_secret_key() {
        let network_key = generate_secret_key();
        println!("{:?}", network_key);
    }

    #[test]
    fn split_key() {
        let input = "mo_AiJm7OZRiM3U2r6S2lEelXNUWcKS3iP-fFF_bvYI:-scJXq0RfnDo3yFFvlYjGg87hM_7durzOwMKxIifWW6aj8CImbs5lGIzdTavpLaUR6Vc1RZwpLeI_58UX9u9gg";
        let a = input.split(":");
        let mut b = a.flat_map(|x| base64::decode_config(x, base64::URL_SAFE_NO_PAD).ok());
        if let Some(x) = b.next() {
            let net_key = NetworkKey{ access_key: x, secret_key: b.next() };
            println!("{:?}", net_key);
        }
    }

    #[test]
    fn split_access_key() {
        let input = "mo_AiJm7OZRiM3U2r6S2lEelXNUWcKS3iP-fFF_bvYI&*^%";
        let a = input.split(":");
        let mut b = a.flat_map(|x| base64::decode_config(x, base64::URL_SAFE_NO_PAD).ok());
        if let Some(x) = b.next() {
            let net_key = NetworkKey{ access_key: x, secret_key: b.next() };
            println!("{:?}", net_key);
        }
    }
}
