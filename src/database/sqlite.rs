use sqlx::SqlitePool;

struct OwnUserDataResult {
	user_id: Vec<u8>,
	display_name: String,
}

/// Returns Ok(true) if the credentials are valid.
pub async fn check_credentials(pool: &SqlitePool, username: &str, pw_hash: &[u8]) -> Result<bool, sqlx::Error> {
	let opt = sqlx::query_scalar!("SELECT password_hash FROM users WHERE username = ?", username)
		.fetch_optional(pool)
		.await?;

	match opt {
		Some(hash) => Ok(hash == *pw_hash),
		None => Ok(false),
	}
}

/// Returns user_id and display_name.
pub async fn get_own_user_data(
	pool: &SqlitePool,
	username: &str,
	password_hash: &[u8],
) -> Result<(String, String), sqlx::Error> {
	let data = sqlx::query_as!(
		OwnUserDataResult,
		"SELECT user_id, display_name FROM users WHERE username = ? AND password_hash = ?",
		username,
		password_hash
	)
	.fetch_one(pool)
	.await?;

	let user_id = String::from_utf8(data.user_id).unwrap();

	Ok((user_id, data.display_name))
}

/// Returns true if the username is available.
pub async fn check_username_availability(pool: &SqlitePool, username: &str) -> Result<bool, sqlx::Error> {
	let exists = sqlx::query_scalar!("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username)
		.fetch_one(pool)
		.await?;

	Ok(exists == 0)
}

/// Adds a new user to the database and returns their user_id.
pub async fn add_new_user(
	pool: &SqlitePool,
	username: &str,
	password: &str,
	display_name: &str,
) -> Result<String, sqlx::Error> {
	let id = uuid::Uuid::new_v4();
	let user_id = id.as_bytes().as_slice();

	let password_hash = blake3::hash(password.as_bytes());
	let password_hash = password_hash.as_bytes().as_slice();

	let res = sqlx::query!(
		"INSERT INTO users (user_id, username, password_hash, display_name) VALUES (?, ?, ?, ?)",
		user_id,
		username,
		password_hash,
		display_name
	)
	.execute(pool)
	.await?;

	if res.rows_affected() == 0 {
		Err(sqlx::Error::RowNotFound)
	} else {
		Ok(id.to_string())
	}
}
