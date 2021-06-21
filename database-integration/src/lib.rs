use std::error;

use access_control::{Backend, FutureOption, FutureResult};
use sqlx::PgPool;

mod error_mapping;
pub mod user;
pub mod utility;

#[derive(Debug, Clone)]
pub struct PostgreSqlBackend {
    pub db: PgPool,
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
