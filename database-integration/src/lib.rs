//! The database-integration crate implements the database functionality of the example application.
//!
//! Part of this implementation is the [`PostgreSqlBackend`] which implements the [`Backend`] trait.
//! This provides access to a `PostgreSql` database in the middleware.
//!
//! The [`Backend`] trait is designed to take in an implementation of the [`access_control::User`] trait, when being implemented.
//! The [`access_control::User`] for the [`PostgreSqlBackend`] is provided by [`user::User`].
//!
//! Additionally, the [`utility`] module provides functions to interact with the `PostgreSql` database in a more general fashion.
//! Currently there is just the [`utility::create_db_pool`] function which is used to create a database pool.
//! This function is currently used in most tests in the [`user`] modules as well as in the main function.

/// Implementation of the database user, which the `PostgreSqlBackend` uses.
///
/// This includes all of the necessary requests to the PostgreSql database to handle users and their sessions.
pub mod user;
/// Utility functions used to work with the PostgreSql database.
pub mod utility;

use access_control::{Backend, FutureOption, FutureResult};
use sqlx::PgPool;
use std::error;

#[derive(Debug, Clone)]
pub struct PostgreSqlBackend {
    pub db: PgPool,
}

impl PostgreSqlBackend {
    pub fn new(db: PgPool) -> PostgreSqlBackend {
        PostgreSqlBackend { db: db }
    }
}

impl Backend<user::User> for PostgreSqlBackend {
    fn get_user(&self, username: impl AsRef<str>) -> FutureOption<user::User> {
        let db = self.db.clone();
        let username = username.as_ref().to_string();

        Box::pin(async move { user::User::look_up_user(&db, &username).await.ok() })
    }

    fn get_user_from_session(&self, session_id: impl AsRef<str>) -> FutureOption<user::User> {
        let db = self.db.clone();
        let session_id = session_id.as_ref().to_string();

        Box::pin(async move {
            user::User::look_up_user_from_session(&db, &session_id)
                .await
                .ok()
        })
    }

    fn register_user(
        &self,
        username: impl AsRef<str>,
        password_hash: impl AsRef<str>,
    ) -> FutureResult<()> {
        let db = self.db.clone();
        let username = username.as_ref().to_string();
        let password_hash = password_hash.as_ref().to_string();

        Box::pin(async move {
            user::User::register_user(&db, &username, &password_hash)
                .await
                .map(|_| ())
                .map_err(|e| Box::new(e) as Box<dyn error::Error>)
        })
    }

    fn store_session(&self, user: &user::User, session_id: impl AsRef<str>) -> FutureResult<()> {
        let db = self.db.clone();
        let user = user.clone();
        let session_id = session_id.as_ref().to_string();

        Box::pin(async move {
            user::User::store_session(&db, &user, &session_id)
                .await
                .map_err(|e| Box::new(e) as Box<dyn error::Error>)?;
            Ok(())
        })
    }

    fn remove_session(&self, session_id: impl AsRef<str>) -> FutureResult<()> {
        let db = self.db.clone();
        let session_id = session_id.as_ref().to_string();

        Box::pin(async move {
            user::User::remove_session(&db, &session_id)
                .await
                .map_err(|e| Box::new(e) as Box<dyn error::Error>)?;
            Ok(())
        })
    }
}
