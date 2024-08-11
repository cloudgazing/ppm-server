// temporary methods. will replace with working ones

pub enum GetUserResult {
	User { username: String, password: String },
	NotFound,
}

pub fn get_user(username: &str) -> Result<GetUserResult, anyhow::Error> {
	// fetch the user from the db
	let password = "temp password".to_string();

	Ok(GetUserResult::User {
		username: username.to_string(),
		password,
	})
}

pub fn user_exists(_username: &str) -> Result<bool, anyhow::Error> {
	// fetch the user from the db

	Ok(true)
}

pub fn hash_password(password: &str) -> String {
	password.to_string()
}
