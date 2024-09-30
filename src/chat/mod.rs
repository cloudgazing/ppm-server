use crate::utils::get_jwt;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use jwt_compact::alg::Hs256Key;
use ppm_models::client::ClientSocketMessage;
use ppm_models::server::{MessageConfirmation, ServerSocketMessage};
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::{net::TcpListener, sync::RwLock};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message as TokioMessage;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};

type SocketSender = SplitSink<WebSocketStream<TlsStream<TcpStream>>, TokioMessage>;
type OpenConnections = Arc<RwLock<HashMap<String, Arc<Mutex<SocketSender>>>>>;
type SocketStream = WebSocketStream<TlsStream<TcpStream>>;

async fn handle_socket(stream: SocketStream, open_connections: OpenConnections, user_id: String) {
	let (sender, mut receiver) = stream.split();

	let own_sender = Arc::new(Mutex::new(sender));

	{
		let mut connections = open_connections.write().await;
		connections.insert(user_id.clone(), own_sender.clone());
	}

	while let Some(message) = receiver.next().await {
		let Ok(message) = message else {
			continue;
		};

		match message {
			TokioMessage::Text(text) => {
				let Ok(ws_msg) = serde_json::from_str::<ClientSocketMessage>(&text) else {
					continue;
				};

				{
					let conn_guard = open_connections.read().await;

					match conn_guard.get(&ws_msg.receiver_id) {
						Some(sender) => {
							let recipient_sender = sender.clone();

							drop(conn_guard);

							let mut recipient_sender = recipient_sender.lock().await;

							let send_res = recipient_sender.send(TokioMessage::Binary(ws_msg.contents)).await;

							drop(recipient_sender);

							let server_message = match send_res {
								Ok(()) => {
									let s = MessageConfirmation::Success;
									let m = ServerSocketMessage::MessageConfirmation(s);
									serde_json::to_string(&m).unwrap()
								}
								Err(_) => {
									// add it to a bucket if the send fails
									let e = MessageConfirmation::Error;
									let m = ServerSocketMessage::MessageConfirmation(e);
									serde_json::to_string(&m).unwrap()
								}
							};

							let mut own_sender = own_sender.lock().await;

							if let Err(e) = own_sender.send(TokioMessage::Text(server_message)).await {
								eprintln!("{}", e);
							}

							drop(own_sender);
						}
						None => {
							drop(conn_guard);
							// add message to a bucket if the person is not online
						}
					}
				}
			}
			TokioMessage::Close(_) => {
				println!("Client disconnected");
			}
			_ => {}
		}
	}

	{
		let mut connections = open_connections.write().await;
		connections.remove(&user_id);
	}
}

pub async fn chat_server(addr: SocketAddr, tls_config: ServerConfig, jwt_key: Arc<Hs256Key>) {
	let acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_config)));
	let listener = TcpListener::bind(addr).await.expect("WS bind error");

	let open_connections: OpenConnections = Arc::new(RwLock::new(HashMap::new()));

	while let Ok((stream, _)) = listener.accept().await {
		let acceptor = acceptor.clone();

		let Ok(tls_stream) = acceptor.accept(stream).await else {
			eprintln!("Failed to establish TLS");
			continue;
		};

		let mut user_id: String = String::new();

		let stream_ft = accept_hdr_async(tls_stream, |req: &Request, resp: Response| match req.uri().query() {
			Some(query_str) => {
				let params: HashMap<_, _> = url::form_urlencoded::parse(query_str.as_bytes()).into_owned().collect();

				let Some(token_str) = params.get("access_token") else {
					return Err(Response::builder().status(401).body(None).unwrap());
				};

				let Ok(token) = get_jwt(token_str, &jwt_key) else {
					return Err(Response::builder().status(401).body(None).unwrap());
				};

				user_id = token.claims().custom.user_id.clone();

				Ok(resp)
			}
			None => Err(Response::builder().status(401).body(None).unwrap()),
		});

		if let Ok(stream) = stream_ft.await {
			let open_connections = open_connections.clone();

			tokio::spawn(handle_socket(stream, open_connections, user_id));
		}
	}
}
