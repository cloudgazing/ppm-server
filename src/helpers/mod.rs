pub mod jwt;

use std::fs::File;
use std::io::BufReader;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};

const CERT_PATH: &str = "./cert/fullchain.pem";
const KEY_PATH: &str = "./cert/privkey.pem";

pub fn get_tls_config() -> anyhow::Result<ServerConfig> {
	let file = File::open(CERT_PATH)?;
	let mut reader = BufReader::new(file);
	let cert_chain: Vec<CertificateDer<'static>> = certs(&mut reader).collect::<std::io::Result<_>>()?;

	let file = File::open(KEY_PATH)?;
	let mut reader = BufReader::new(file);
	let key_der: PrivateKeyDer<'static> = pkcs8_private_keys(&mut reader).next().unwrap().map(Into::into)?;

	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(cert_chain, key_der)?;

	Ok(config)
}
