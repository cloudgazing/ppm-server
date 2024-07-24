use chrono::{Duration, Utc};
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use jwt_compact::{
	alg::{Hs256, Hs256Key},
	prelude::*,
};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

mod models;
use models::{ClientMessage, TokenClaims};

fn generate_jwt(key: &Hs256Key, user_id: String) -> Result<String, jwt_compact::CreationError> {
	let custom_claims = TokenClaims { user_id };

	let time_options = TimeOptions::default();

	let header = Header::empty().with_key_id("my-key");

	let claims = Claims::new(custom_claims)
		.set_duration_and_issuance(&time_options, Duration::days(10))
		.set_not_before(Utc::now());

	Hs256.token(&header, &claims, &key)
}

fn get_jwt(token_string: String, verifying_key: &Hs256Key) -> Result<Token<TokenClaims>, anyhow::Error> {
	let token = UntrustedToken::new(&token_string)?;

	let token: Token<TokenClaims> = Hs256.validator(verifying_key).validate(&token)?;

	let time_options = TimeOptions::default();

	token
		.claims()
		.validate_expiration(&time_options)?
		.validate_maturity(&time_options)?;

	Ok::<_, anyhow::Error>(token)
}

async fn handle_connection(stream: tokio::net::TcpStream) {
	let ws_stream = accept_async(stream).await.expect("Error during WebSocket handshake");

	println!("New WebSocket connection");

	let (mut ws_sender, mut ws_receiver) = ws_stream.split();

	while let Some(message) = ws_receiver.next().await {
		match message {
			Ok(Message::Text(text)) => {
				match serde_json::from_str::<ClientMessage>(&text) {
					Ok(ClientMessage::LoginData(data)) => {
						// validate login data
						println!("Received login data: {:?}", data);

						// get user_id
						let user_id = "test-user-id".to_string();

						let key = Hs256Key::new(b"super_secret_key_donut_steel");

						let token_string = generate_jwt(&key, user_id);

						match token_string {
							Ok(token_string) => {
								ws_sender
									.send(Message::Text(token_string))
									.await
									.expect("Failed to send auth token");
							}
							Err(e) => {
								println!("Error: {e}");
								ws_sender
									.send(Message::Text("There was an error loging you in".to_string()))
									.await
									.expect("Failed to send auth token");
							}
						}
					}
					Ok(ClientMessage::SentMessage(data)) => {
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
					Err(e) => {
						println!("Error: {e}");
					}
				}
			}
			Ok(Message::Close(_)) => {
				println!("Client disconnected");
			}
			Err(e) => {
				println!("Error: {:?}", e);
			}
			_ => (),
		}
	}
}

#[tokio::main]
async fn main() {
	let addr = "127.0.0.1:3030";
	let listener = TcpListener::bind(addr).await.expect("Failed to bind");

	println!("WebSocket server running on ws://{}", addr);

	while let Ok((stream, _)) = listener.accept().await {
		tokio::spawn(handle_connection(stream));
	}
}
