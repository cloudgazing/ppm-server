mod auth;
mod chat;
mod db;
mod helpers;

use chat::handle_websocket;
use clap::Parser;
use helpers::get_tls_config;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
	#[arg(short, long, default_value_t = local_ip_address::local_ip().unwrap().to_string())]
	address: String,
	#[arg(long, default_value_t = 4040)]
	auth_port: u16,
	#[arg(long, default_value_t = 8080)]
	chat_port: u16,
	#[arg(short, long, default_value_t = 4)]
	workers: usize,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
	let Args {
		address,
		auth_port,
		chat_port,
		workers,
	} = Args::parse();

	let tls_config = get_tls_config().unwrap();

	println!("Auth server running on {address} port {auth_port}");

	let addr = address.clone();
	let auth_server = tokio::spawn(async move {
		let server = auth::auth_server(addr, auth_port, workers, tls_config);

		server.unwrap().await
	});

	println!("Chat server running on {address} port {chat_port}");
	let tls_config = get_tls_config().unwrap();
	let ws_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));
	let ws_listener = TcpListener::bind((address, chat_port)).await.expect("WS bind error");

	let chat_server = tokio::spawn(async move {
		while let Ok((stream, _)) = ws_listener.accept().await {
			let acceptor = ws_acceptor.clone();

			let tls_stream = match acceptor.accept(stream).await {
				Ok(stream) => stream,
				Err(e) => {
					eprintln!("Failed to establish TLS: {:?}", e);
					continue;
				}
			};

			tokio::spawn(handle_websocket(tls_stream));
		}
	});

	tokio::signal::ctrl_c().await.expect("Shutdown signal error");

	println!("Stoppng servers...");

	auth_server.abort();
	chat_server.abort();

	Ok(())
}
