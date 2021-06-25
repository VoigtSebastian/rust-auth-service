use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use std::env;

/// Tries to create a postgres database pool from the DATABASE_URL.
///
/// Calls dotenv(), so that the .env file is used when possible.
pub async fn create_db_pool() -> anyhow::Result<sqlx::PgPool> {
    dotenv::dotenv().ok();
    let database_uri = env::var("DATABASE_URL").context("Database URL not set".to_string())?;

    PgPoolOptions::new()
        .max_connections(5)
        .connect(database_uri.as_str())
        .await
        .context("Postgres connection not successful".to_string())
}
