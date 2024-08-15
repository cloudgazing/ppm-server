use crate::db;
use crate::helpers::jwt::{generate_jwt, get_jwt};

use std::sync::Arc;

use actix_csrf::extractor::{Csrf, CsrfHeader};
use actix_web::{web, Responder};
use jwt_compact::alg::Hs256Key;
use ppm_models::client::auth::{LoginData, SignupData};
use ppm_models::server;
use ppm_models::server::auth::{BasicResponse, LoginConfirmation, SignupConfirmation};

pub async fn auth() -> impl Responder {
	actix_web::HttpResponse::Ok().finish()
}

pub async fn login(_: Csrf<CsrfHeader>, data: web::Bytes, jwt_key: Arc<Hs256Key>) -> web::Bytes {
	let data = match std::str::from_utf8(&data) {
		Ok(s) => s,
		Err(_) => {
			return LoginConfirmation::failure(server::error::AUTH_INVALID_BYTES)
				.serialize()
				.unwrap()
				.into();
		}
	};

	let login_data = match serde_json::from_str::<LoginData>(data) {
		Ok(data) => data,
		Err(_) => {
			return LoginConfirmation::failure(server::error::AUTH_INVALID_LOGIN_DATA)
				.serialize()
				.unwrap()
				.into();
		}
	};

	let user_result = match db::get_user(&login_data.username) {
		Ok(user) => user,
		Err(_) => {
			return LoginConfirmation::failure(server::error::AUTH_INTERNAL_ERROR)
				.serialize()
				.unwrap()
				.into();
		}
	};

	match user_result {
		db::GetUserResult::User { password, .. } => {
			if db::hash_password(&password) == login_data.password {
				let jwt = generate_jwt(&jwt_key, "temp user_id".to_string()).unwrap();

				LoginConfirmation::success(jwt).serialize().unwrap().into()
			} else {
				LoginConfirmation::failure(server::error::LOGIN_WRONG_PASSWORD)
					.serialize()
					.unwrap()
					.into()
			}
		}
		db::GetUserResult::NotFound => LoginConfirmation::failure(server::error::LOGIN_USERNAME_NOT_FOUND)
			.serialize()
			.unwrap()
			.into(),
	}
}

pub async fn signup(_: Csrf<CsrfHeader>, data: web::Bytes, jwt_key: Arc<Hs256Key>) -> web::Bytes {
	let data = match std::str::from_utf8(&data) {
		Ok(s) => s,
		Err(_) => {
			return SignupConfirmation::failure(server::error::AUTH_INVALID_BYTES)
				.serialize()
				.unwrap()
				.into();
		}
	};

	let signup_data = match serde_json::from_str::<SignupData>(data) {
		Ok(data) => data,
		Err(_) => {
			return SignupConfirmation::failure(server::error::AUTH_INVALID_SIGNUP_DATA)
				.serialize()
				.unwrap()
				.into();
		}
	};

	match db::user_exists(&signup_data.username) {
		Ok(exists) => {
			if !exists {
				// make the new user
				let jwt = generate_jwt(&jwt_key, "temp user_id".to_string()).unwrap();

				SignupConfirmation::success(jwt).serialize().unwrap().into()
			} else {
				SignupConfirmation::failure(server::error::SIGNUP_USERNAME_TAKEN)
					.serialize()
					.unwrap()
					.into()
			}
		}
		Err(_) => SignupConfirmation::failure(server::error::AUTH_INTERNAL_ERROR)
			.serialize()
			.unwrap()
			.into(),
	}
}

pub async fn validate(_: Csrf<CsrfHeader>, data: web::Bytes, jwt_key: Arc<Hs256Key>) -> web::Bytes {
	match std::str::from_utf8(&data) {
		Ok(token) => match get_jwt(token.to_string(), &jwt_key) {
			Ok(_) => serde_json::to_string(&BasicResponse::Ok(true)).unwrap().into(),
			Err(_) => serde_json::to_string(&BasicResponse::Ok(false)).unwrap().into(),
		},
		Err(_) => serde_json::to_string(&BasicResponse::<bool>::Err).unwrap().into(),
	}
}
