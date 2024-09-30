mod api;
mod chat;
mod database;
mod utils;

use std::sync::Arc;

use clap::Parser;
use jwt_compact::alg::Hs256Key;

const CERT_PATH: &str = "./cert/fullchain.pem";
const KEY_PATH: &str = "./cert/privkey.pem";
const CORS_ALLOWED_ORIGIN: &str = env!("CORS_ALLOWED_ORIGIN");
const DATABASE_URL: &str = env!("DATABASE_URL");

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
	#[arg(short, long, default_value_t = 4040)]
	auth_port: u16,
	#[arg(short, long, default_value_t = 8080)]
	chat_port: u16,
	#[arg(short, long, default_value_t = 4)]
	workers: usize,
	#[arg(short, long, default_value = "super_ultra_mega_sercret_key")]
	jwt_key: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
	let Args {
		auth_port,
		chat_port,
		workers,
		jwt_key,
	} = Args::parse();

	let address = local_ip_address::local_ip()?;

	let jwt_key = Arc::new(Hs256Key::new(jwt_key));

	let auth_server = {
		let jwt_key = jwt_key.clone();

		let addr = std::net::SocketAddr::new(address, auth_port);
		let tls_config = utils::get_tls_config(CERT_PATH, KEY_PATH)?;

		tokio::spawn(api::api_server(addr, tls_config, workers, jwt_key, DATABASE_URL, CORS_ALLOWED_ORIGIN).await?)
	};

	println!("Auth server running on {address} port {auth_port}");

	let chat_server = {
		let jwt_key = jwt_key.clone();

		let addr = std::net::SocketAddr::new(address, chat_port);
		let tls_config = utils::get_tls_config(CERT_PATH, KEY_PATH)?;

		tokio::spawn(chat::chat_server(addr, tls_config, jwt_key))
	};

	println!("Chat server running on {address} port {chat_port}");

	tokio::signal::ctrl_c().await.expect("Shutdown signal error");

	println!("\n Stopping servers... \n");

	auth_server.abort();
	chat_server.abort();

	Ok(())
}
