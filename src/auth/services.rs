use crate::db;
use crate::helpers::jwt::generate_jwt;

use actix_csrf::extractor::{Csrf, CsrfHeader};
use actix_web::{web, Responder};
use jwt_compact::alg::Hs256Key;
use ppm_models::client::auth::{LoginData, SignupData};
use ppm_models::server;
use ppm_models::server::auth::{LoginConfirmation, SignupConfirmation};

#[actix_web::get("/auth")]
pub async fn auth() -> impl Responder {
	println!("--auth--");

	actix_web::HttpResponse::Ok().finish()
}

#[actix_web::post("/login")]
pub async fn login(_: Csrf<CsrfHeader>, data: web::Bytes) -> web::Bytes {
	println!("--login--");

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
				let key = Hs256Key::new(b"super_secret_key_donut_steel");
				let jwt = generate_jwt(&key, "temp user_id".to_string()).unwrap();

				LoginConfirmation::success(jwt)
					.serialize()
					.unwrap()
					.into()
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

#[actix_web::post("/signup")]
async fn signup(_: Csrf<CsrfHeader>, data: web::Bytes) -> web::Bytes {
	println!("--signup--");

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
				let key = Hs256Key::new(b"super_secret_key_donut_steel");
				let jwt = generate_jwt(&key, "temp user_id".to_string()).unwrap();

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
