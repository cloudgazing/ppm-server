mod auth;

use std::sync::Arc;

use actix_web::dev::Server;
use actix_web::{web, App, HttpServer};
use jwt_compact::alg::Hs256Key;
use rustls::ServerConfig;
use sqlx::sqlite::SqlitePoolOptions;

const DATABASE_URL: &str = env!("DATABASE_URL");

pub async fn api_server(
	worker_count: usize,
	bind_addrs: (String, u16),
	tls_config: ServerConfig,
	jwt_key: Arc<Hs256Key>,
) -> std::io::Result<Server> {
	let pool = SqlitePoolOptions::new()
		.max_connections(10)
		.connect(DATABASE_URL)
		.await
		.unwrap();

	let server = HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(pool.clone()))
			.app_data(web::Data::new(jwt_key.clone()))
			.service(
				web::scope("/auth")
					.wrap(auth::auth_middleware())
					.service(auth::login)
					.service(auth::signup),
			)
	})
	.workers(worker_count)
	.bind_rustls_0_23(bind_addrs, tls_config)?
	.run();

	Ok(server)
}
