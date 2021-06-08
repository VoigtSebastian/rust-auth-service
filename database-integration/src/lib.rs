use std::future::Future;
use std::pin::Pin;

use access_control::{Backend, User};
use sqlx::PgPool;

mod error_mapping;
pub mod user;
pub mod utility;

#[derive(Debug, Clone)]
pub struct PostgreSqlBackend {
    pub db: PgPool,
}

impl Backend<User> for PostgreSqlBackend {
    fn get_user(&self, email: &str, password: &str) -> Pin<Box<dyn Future<Output = Option<User>>>> {
        let db = self.db.clone();
        let email = email.to_string();
        let password = password.to_string();

        Box::pin(async move {
            let user = user::User::look_up_user(&db, &email, &password)
                .await
                .ok()?;
            Some(User {
                name: user.email.into(),
                permissions: "Admin".to_string(),
            })
        })
    }
}
