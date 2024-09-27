use crate::database::sqlite::{add_new_user, check_credentials, check_username_availability, get_own_user_data};
use crate::helpers::jwt::generate_jwt;

use std::sync::Arc;

use actix_web::http::header;
use actix_web::web;
use jwt_compact::alg::Hs256Key;
use ppm_models::new::client::auth::{LoginData, SignupData};
use ppm_models::new::server::{
	auth::AuthResponse,
	error::{LoginError, SignupError},
};
use sqlx::SqlitePool;

const CORS_ALLOWED_ORIGIN: &str = env!("CORS_ALLOWED_ORIGIN");

#[actix_web::post("/login")]
pub async fn login(
	pool: web::Data<SqlitePool>,
	jwt_key: web::Data<Arc<Hs256Key>>,
	data: web::Json<LoginData>,
) -> web::Json<AuthResponse> {
	let pw_hash = blake3::hash(data.password.as_bytes());
	let pw_hash = pw_hash.as_bytes().as_slice();

	let check_resp = check_credentials(&pool, &data.username, pw_hash).await;

	match check_resp {
		Ok(true) => {
			let Ok((user_id, display_name)) = get_own_user_data(&pool, &data.username, pw_hash).await else {
				return web::Json(AuthResponse::error(SignupError::Internal.as_str().to_string()));
			};

			let Ok(auth_token) = generate_jwt(&jwt_key, &user_id) else {
				return web::Json(AuthResponse::error(SignupError::Internal.as_str().to_string()));
			};

			web::Json(AuthResponse::success(user_id, display_name, auth_token))
		}
		_ => web::Json(AuthResponse::error(LoginError::WrongCredentials.as_str().to_string())),
	}
}

#[actix_web::post("/signup")]
pub async fn signup(
	pool: web::Data<SqlitePool>,
	jwt_key: web::Data<Arc<Hs256Key>>,
	data: web::Json<SignupData>,
) -> web::Json<AuthResponse> {
	let check_resp = check_username_availability(&pool, &data.username).await;

	match check_resp {
		Ok(true) => {
			let Ok(user_id) = add_new_user(&pool, &data.username, &data.password, &data.display_name).await else {
				return web::Json(AuthResponse::error(SignupError::Internal.as_str().to_string()));
			};

			let Ok(auth_token) = generate_jwt(&jwt_key, &user_id) else {
				return web::Json(AuthResponse::error(SignupError::Internal.as_str().to_string()));
			};

			web::Json(AuthResponse::success(user_id, data.display_name.clone(), auth_token))
		}
		Ok(false) => web::Json(AuthResponse::error(SignupError::UsernameTaken.as_str().to_string())),
		_ => web::Json(AuthResponse::error(SignupError::Internal.as_str().to_string())),
	}
}

pub fn auth_middleware() -> actix_cors::Cors {
	let cors = actix_cors::Cors::default()
		.allowed_origin(CORS_ALLOWED_ORIGIN)
		.allowed_methods(["POST"])
		.allowed_headers([
			header::CONTENT_TYPE,
			header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
			header::ACCEPT,
			header::ACCESS_CONTROL_ALLOW_ORIGIN,
		]);

	cors
}
