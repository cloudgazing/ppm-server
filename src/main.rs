use futures_util::stream::StreamExt;
use jwt_compact::alg::Hs256Key;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

use ppm_models::client::{AuthData, ClientMessage};
use ppm_models::server::{LoginConfirmation, SignupConfirmation, TokenClaims};

async fn get_acceptor() -> Result<TlsAcceptor, anyhow::Error> {
	let cert_path = "./cert/fullchain.pem";
	let key_path = "./cert/privkey.pem";

	let file = std::fs::File::open(cert_path)?;
	let mut reader = std::io::BufReader::new(file);
	let cert_chain: Vec<CertificateDer<'static>> = certs(&mut reader).collect::<std::io::Result<_>>()?;

	let file = std::fs::File::open(key_path)?;
	let mut reader = std::io::BufReader::new(file);
	let key_der: PrivateKeyDer<'static> = pkcs8_private_keys(&mut reader).next().unwrap().map(Into::into)?;

	let config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(cert_chain, key_der)?;

	let acceptor = TlsAcceptor::from(Arc::new(config));

	Ok(acceptor)
}

fn generate_jwt(key: &Hs256Key, user_id: String) -> Result<String, jwt_compact::CreationError> {
	use jwt_compact::{alg::Hs256, AlgorithmExt, Claims, Header, TimeOptions};

	let time_options = TimeOptions::default();

	let custom_claims = TokenClaims { user_id };

	let header = Header::empty().with_key_id("my-key");

	let claims = Claims::new(custom_claims)
		.set_duration_and_issuance(&time_options, chrono::Duration::days(10))
		.set_not_before(chrono::Utc::now());

	Hs256.token(&header, &claims, &key)
}

fn get_jwt(token_string: String, verifying_key: &Hs256Key) -> Result<jwt_compact::Token<TokenClaims>, anyhow::Error> {
	use jwt_compact::{alg::Hs256, prelude::UntrustedToken, AlgorithmExt, TimeOptions};

	let time_options = TimeOptions::default();

	let token = UntrustedToken::new(&token_string)?;
	let token = Hs256.validator(verifying_key).validate(&token)?;

	token
		.claims()
		.validate_expiration(&time_options)?
		.validate_maturity(&time_options)?;

	Ok::<_, anyhow::Error>(token)
}

async fn handle_websocket(stream: TlsStream<TcpStream>) {
	let ws_stream = accept_async(stream).await.expect("Error during WebSocket handshake");

	println!("New WebSocket connection");

	let (mut sender, mut receiver) = ws_stream.split();

	while let Some(message) = receiver.next().await {
		let message = match message {
			Ok(message) => message,
			Err(e) => {
				println!("WebSocket error: {e}");
				continue;
			}
		};

		match message {
			Message::Text(text) => {
				let client_message: ClientMessage = match serde_json::from_str(&text) {
					Ok(message) => message,
					Err(e) => {
						println!("Error: {e}");
						continue;
					}
				};

				match client_message {
					ClientMessage::UserMessage(data) => {
						let key = Hs256Key::new(b"super_secret_key_donut_steel");
						let token = get_jwt(data.access_token, &key);

						match token {
							Ok(token) => {
								let user_id = &token.claims().custom.user_id;
								println!("user_id: {:?}", user_id);
							}
							Err(e) => {
								// send something that prompts the user to back in
								println!("Invalid token: {e}");
							}
						}
					}
					ClientMessage::WelcomeValidation(data) => {
						println!("welcome: {:#?}", data);
					}
				}
			}
			Message::Close(_) => {
				println!("Client disconnected");
			}
			_ => (),
		}
	}
}

async fn handle_https(data: &str) {
	match serde_json::from_str::<AuthData>(data).unwrap() {
		AuthData::Login(login_data) => {
			//TODO: validate login data

			//TODO: get user_id from db
			let user_id = "test-user-id".to_string();

			let key = Hs256Key::new(b"super_secret_key_donut_steel");

			let token = generate_jwt(&key, user_id);

			match token {
				Ok(access_token) => {
					let login_confirmation = LoginConfirmation { access_token };

					let data_string = serde_json::to_string(&login_confirmation).unwrap();

					// send the login confirmation
				}
				Err(e) => {
					// send back an error
				}
			}
		}
		AuthData::Signup(signup_data) => {
			// validate signup data
			println!("Received signup data: {:?}", signup_data);

			// get user_id
			let user_id = "test-user-id".to_string();

			let key = Hs256Key::new(b"super_secret_key_donut_steel");

			let token = generate_jwt(&key, user_id);

			match token {
				Ok(access_token) => {
					let signup_confirmation = SignupConfirmation { access_token };

					let data_string = serde_json::to_string(&signup_confirmation).unwrap();

					// send the signup confirmation
				}
				Err(e) => {
					// send back an error
				}
			}
		}
	}
}

#[tokio::main]
async fn main() {
	// used for testing
	let addr = "192.168.86.250";
	let ws_addr = format!("{}:8080", addr);
	let http_addr = format!("{}:4040", addr);

	let acceptor = get_acceptor().await.unwrap();

	let listener = TcpListener::bind(ws_addr).await.expect("Failed to bind address");

	println!("Server running on {}", addr);
	println!("WSS on port 8080");
	println!("HTTPS on port 4040");

	while let Ok((stream, _)) = listener.accept().await {
		let acceptor = acceptor.clone();

		let tls_stream = match acceptor.accept(stream).await {
			Ok(stream) => stream,
			Err(e) => {
				eprintln!("Failed to establish TLS: {:?}", e);
				continue;
			}
		};

		tokio::spawn(handle_websocket(tls_stream));
	}
}
