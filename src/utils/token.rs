use chrono::{Duration, Utc};
use jwt_compact::alg::{Hs256, Hs256Key};
use jwt_compact::{AlgorithmExt, Claims, Header, TimeOptions, Token, UntrustedToken};
use ppm_models::server::TokenClaims;

pub fn generate_jwt(key: &Hs256Key, user_id: &str) -> Result<String, jwt_compact::CreationError> {
	let user_id = user_id.to_string();

	let time_options = TimeOptions::default();

	let custom_claims = TokenClaims { user_id };

	let header = Header::empty().with_key_id("my-key");

	let claims = Claims::new(custom_claims)
		.set_duration_and_issuance(&time_options, Duration::days(10))
		.set_not_before(Utc::now());

	Hs256.token(&header, &claims, key)
}

pub fn get_jwt(token_str: &str, verifying_key: &Hs256Key) -> anyhow::Result<Token<TokenClaims>> {
	let time_options = TimeOptions::default();

	let token = UntrustedToken::new(token_str)?;
	let token: Token<TokenClaims> = Hs256.validator(verifying_key).validate(&token)?;

	token
		.claims()
		.validate_expiration(&time_options)?
		.validate_maturity(&time_options)?;

	Ok(token)
}
