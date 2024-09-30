mod auth;

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::dev::Server;
use actix_web::{web, App, HttpServer};
use jwt_compact::alg::Hs256Key;
use rustls::ServerConfig;
use sqlx::sqlite::SqlitePoolOptions;

pub async fn api_server(
	addr: SocketAddr,
	tls_config: ServerConfig,
	workers: usize,
	jwt_key: Arc<Hs256Key>,
	database_url: &'static str,
	cors_allowed_origin: &'static str,
) -> std::io::Result<Server> {
	let pool = SqlitePoolOptions::new()
		.max_connections(10)
		.connect(database_url)
		.await
		.unwrap();

	let server = HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(pool.clone()))
			.app_data(web::Data::new(jwt_key.clone()))
			.service(
				web::scope("/auth")
					.wrap(auth::middleware(cors_allowed_origin))
					.service(auth::login)
					.service(auth::signup),
			)
	})
	.workers(workers)
	.bind_rustls_0_23(addr, tls_config)?
	.run();

	Ok(server)
}
