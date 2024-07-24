use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct TokenClaims {
	pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginData {
	pub access_key: String,
	pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SentMessage {
	pub access_token: String,
	pub user_id: String,
	// change to encrypted message
	pub content: String,
}

#[derive(Serialize, Deserialize)]
pub enum ClientMessage {
	LoginData(LoginData),
	SentMessage(SentMessage),
}

#[derive(Serialize, Deserialize)]
pub struct NewMessage {
	pub user_id: String,
	pub content: String,
}

#[derive(Serialize, Deserialize)]
pub enum ServerMessage {
	NewMessage(NewMessage),
}
