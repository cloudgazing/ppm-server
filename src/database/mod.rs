pub mod sqlite;

use std::str::FromStr;

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Executor, SqlitePool};

const DB_DIR: &str = "./db";
const SQLITE_FILE: &str = constcat::concat!(DB_DIR, "/server_data.sqlite3");
const SQLITE_URL: &str = constcat::concat!("sqlite://", SQLITE_FILE);

pub async fn create_sqlite() -> Result<(), sqlx::Error> {
	if !std::path::Path::new(DB_DIR).exists() {
		println!("Creating db directory");

		std::fs::create_dir(DB_DIR)?;
	}

	if !std::path::Path::new(SQLITE_FILE).exists() {
		println!("Creating server_data.sqlite3 file");

		std::fs::File::create(SQLITE_FILE)?;
	}

	let conn = SqliteConnectOptions::from_str(SQLITE_URL)?;

	let pool = SqlitePool::connect_with(conn).await?;

	pool.execute(
		r#"
		CREATE TABLE "users" (
			"user_id" BLOB NOT NULL,
			"username" TEXT NOT NULL,
			"password_hash" BLOB NOT NULL,
			"display_name" TEXT NOT NULL,
			PRIMARY KEY ("user_id"),
			CONSTRAINT unique_value UNIQUE ("username")
		);
		"#,
	)
	.await?;

	println!("Created {SQLITE_FILE}");

	Ok(())
}
