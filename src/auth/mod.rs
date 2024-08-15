mod services;

use std::sync::Arc;

use actix_csrf::extractor::{Csrf, CsrfHeader};
use actix_csrf::CsrfMiddleware;
use actix_web::http::{header, Method};
use actix_web::{dev::Server, web, App, HttpServer};
use jwt_compact::alg::Hs256Key;
use rand::rngs::StdRng;
use rustls::ServerConfig;

pub fn auth_server(
	address: String,
	port: u16,
	workers: usize,
	tls_config: ServerConfig,
	jwt_key: Arc<Hs256Key>,
) -> std::io::Result<Server> {
	let server = HttpServer::new(move || {
		let csrf = CsrfMiddleware::<StdRng>::new()
			.http_only(false)
			.domain("cloudgazing.dev")
			.same_site(Some(actix_web::cookie::SameSite::None))
			.secure(true)
			.set_cookie(Method::GET, "/auth");

		let cors = actix_cors::Cors::default()
			.allowed_origin("https://chat.cloudgazing.dev")
			.allowed_methods(["GET", "POST", "OPTIONS"])
			.allowed_headers(vec![
				header::CONTENT_TYPE,
				header::AUTHORIZATION,
				header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
				header::ACCEPT,
				header::ACCESS_CONTROL_ALLOW_ORIGIN,
				header::HeaderName::from_bytes(b"Csrf-Token").unwrap(),
			])
			.supports_credentials();

		App::new()
			.app_data(csrf.cookie_config())
			.wrap(csrf)
			.wrap(cors)
			.service(web::resource("/auth").route(web::get().to(services::auth)))
			.service(web::resource("/auth/login").route(web::post().to({
				let jwt_key = jwt_key.clone();

				move |csrf: Csrf<CsrfHeader>, data: web::Bytes| services::login(csrf, data, jwt_key.clone())
			})))
			.service(web::resource("/auth/signup").route(web::post().to({
				let jwt_key = jwt_key.clone();

				move |csrf: Csrf<CsrfHeader>, data: web::Bytes| services::signup(csrf, data, jwt_key.clone())
			})))
			.service(web::resource("/auth/validate").route(web::post().to({
				let jwt_key = jwt_key.clone();

				move |csrf: Csrf<CsrfHeader>, data: web::Bytes| services::validate(csrf, data, jwt_key.clone())
			})))
	})
	.workers(workers)
	.bind_rustls_0_23((address, port), tls_config)?
	.run();

	Ok(server)
}
