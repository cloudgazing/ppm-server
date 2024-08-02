use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use jwt_compact::alg::Hs256Key;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

use ppm_models::client::{ClientMessage, LoginData, SignupData};
use ppm_models::server::{LoginConfirmation, SignupConfirmation, TokenClaims};

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

async fn handle_connection(stream: TlsStream<TcpStream>) {
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
				let client_message = match serde_json::from_str::<ClientMessage>(&text) {
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

fn login(login_data: LoginData) {
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

fn signup(signup_data: SignupData) {
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

#[tokio::main]
async fn main() {
	// used for testing
	let address = "192.168.86.250:8080";

	let cert_path = "./cert/fullchain.pem";
	let key_path = "./cert/privkey.pem";

	let file = std::fs::File::open(cert_path).expect("Cert file error");
	let mut reader = std::io::BufReader::new(file);
	let cert_chain: std::io::Result<Vec<CertificateDer<'static>>> = certs(&mut reader).collect();
	let cert_chain = cert_chain.unwrap();

	let file = std::fs::File::open(key_path).expect("Key file error");
	let mut reader = std::io::BufReader::new(file);
	let key_der: std::io::Result<PrivateKeyDer<'static>> =
		pkcs8_private_keys(&mut reader).next().unwrap().map(Into::into);
	let key_der = key_der.unwrap();

	let config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(cert_chain, key_der)
		.expect("Error creating server config");

	let acceptor = TlsAcceptor::from(Arc::new(config));
	let listener = TcpListener::bind(address).await.expect("Failed to bind address");

	println!("WebSocket server running on {}", address);

	while let Ok((stream, _)) = listener.accept().await {
		let acceptor = acceptor.clone();

		let tls_stream = match acceptor.accept(stream).await {
			Ok(stream) => stream,
			Err(e) => {
				eprintln!("Failed to establish TLS: {:?}", e);
				continue;
			}
		};

		tokio::spawn(handle_connection(tls_stream));
	}
}
