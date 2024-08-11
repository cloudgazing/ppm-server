mod services;

use actix_csrf::CsrfMiddleware;
use actix_web::http::Method;
use actix_web::App;
use actix_web::{dev::Server, HttpServer};
use rand::rngs::StdRng;
use rustls::ServerConfig;

pub fn auth_server(address: String, port: u16, workers: usize, tls_config: ServerConfig) -> std::io::Result<Server> {
	let server = HttpServer::new(|| {
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
				actix_web::http::header::CONTENT_TYPE,
				actix_web::http::header::AUTHORIZATION,
				actix_web::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
				actix_web::http::header::ACCEPT,
				actix_web::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
				actix_web::http::header::HeaderName::from_bytes(b"Csrf-Token").unwrap(),
			])
			.supports_credentials();

		App::new()
			.app_data(csrf.cookie_config())
			.wrap(csrf)
			.wrap(cors)
			.service(services::auth)
			.service(services::login)
			.service(services::signup)
	})
	.workers(workers)
	.bind_rustls_0_23((address, port), tls_config)?
	.run();

	Ok(server)
}
