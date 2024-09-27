use crate::helpers::jwt::get_jwt;

use core::str;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use jwt_compact::alg::Hs256Key;
use ppm_models::old::client::message::WsMessage;
use ppm_models::old::database::MessageBundle;
use ppm_models::old::server::error::MessageStatusError;
use ppm_models::old::server::message::WsServerMessage;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message as TokioMessage;

const DATABASE_URL: &str = env!("DATABASE_URL");

pub async fn handle_websocket(stream: TlsStream<TcpStream>, jwt_key: Arc<Hs256Key>) {
	let stream_ft = accept_hdr_async(stream, |req: &Request, resp: Response| {
		let token_opt = req.uri().query().map_or(Err(()), |val| {
			val.split('&')
				.find(|param| param.starts_with("token="))
				.map_or(Ok(None), |val| Ok(val.split('=').nth(1)))
		});

		let token = match token_opt {
			Ok(Some(token_str)) => token_str,
			Ok(None) => return Err(Response::builder().status(401).body(None).unwrap()),
			Err(_) => return Err(Response::builder().status(400).body(None).unwrap()),
		};

		if get_jwt(token, &jwt_key).is_err() {
			return Err(Response::builder().status(401).body(None).unwrap());
		}

		Ok(resp)
	});

	let Ok(ws_stream) = stream_ft.await else {
		return;
	};

	let (mut sender, mut receiver) = ws_stream.split();

	while let Some(message) = receiver.next().await {
		let Ok(message) = message else {
			continue;
		};

		match message {
			TokioMessage::Text(text) => {
				let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) else {
					continue;
				};

				match get_jwt(&ws_msg.jwt, &jwt_key) {
					Ok(token) => {
						let user_id = &token.claims().custom.user_id;

						let sender_id = user_id.clone();
						let message_id = ws_msg.message_id;
						let _receiver_id = ws_msg.receiver_id;

						let message_bundle = MessageBundle::new(
							message_id.clone(),
							ws_msg.chat_id,
							sender_id,
							ws_msg.message,
							ws_msg.timestamp,
						);

						// store it in the db
						let pool = SqlitePoolOptions::new()
							.max_connections(5)
							.connect(DATABASE_URL)
							.await
							.unwrap();

						let bundle = message_bundle.clone().into_raw();

						let add_msg: Result<(), String> = Ok(());

						match add_msg {
							Ok(()) => {
								let msg_update = WsServerMessage::successful_message_status(message_id);
								let msg_update = serde_json::to_string(&msg_update).unwrap();
								let tokio_message = TokioMessage::Text(msg_update);

								_ = sender.send(tokio_message).await;

								// send the message to recipient
								//
							}
							Err(_) => {
								let msg_update =
									WsServerMessage::error_message_status(message_id, MessageStatusError::Internal);
								let msg_update = serde_json::to_string(&msg_update).unwrap();
								let tokio_message = TokioMessage::Text(msg_update);

								_ = sender.send(tokio_message).await;
							}
						}
					}
					Err(e) => {
						// send something that prompts the user to back in
						println!("Invalid token: {e}");
					}
				}
			}
			TokioMessage::Close(_) => {
				println!("Client disconnected");
			}
			_ => (),
		}
	}
}
