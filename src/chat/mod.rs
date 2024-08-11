use futures_util::StreamExt;
use jwt_compact::alg::Hs256Key;
use ppm_models::client::message::Message;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::{accept_async, tungstenite};

use crate::helpers::jwt::get_jwt;

pub async fn handle_websocket(stream: TlsStream<TcpStream>) {
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
			tungstenite::Message::Text(text) => {
				let client_message: Message = match serde_json::from_str(&text) {
					Ok(message) => message,
					Err(e) => {
						println!("Error: {e}");
						continue;
					}
				};

				match client_message {
					Message::UserMessage(data) => {
						let key = Hs256Key::new(b"super_secret_key_donut_steel");
						let token = get_jwt(data.jwt, &key);

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
					Message::WelcomeResponse(data) => {
						println!("welcome: {:#?}", data);
					}
				}
			}
			tungstenite::Message::Close(_) => {
				println!("Client disconnected");
			}
			_ => (),
		}
	}
}
