use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use access_control::{Backend, User as UserTrait};
use sqlx::PgPool;

mod error_mapping;
pub mod user;
pub mod utility;

#[derive(Debug, Clone)]
pub struct PostgreSqlBackend {
    pub db: PgPool,
}

impl UserTrait for user::User {
    fn name(&self) -> &str {
        &self.username
    }

    fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }
}

impl Backend<user::User> for PostgreSqlBackend {
    fn get_user(
        &self,
        username: &str,
        password: &str,
    ) -> Pin<Box<dyn Future<Output = Option<user::User>>>> {
        let db = self.db.clone();
        let username = username.to_string();
        let password = password.to_string();

        Box::pin(async move {
            user::User::look_up_user(&db, &username, &password)
                .await
                .ok()
        })
    }

    fn get_user_from_session(
        &self,
        session_id: &str,
    ) -> Pin<Box<dyn Future<Output = Option<user::User>>>> {
        let db = self.db.clone();
        let session_id = session_id.to_string();

        Box::pin(async move {
            user::User::look_up_user_from_session(&db, &session_id)
                .await
                .ok()
        })
    }
}
