use chrono::{DateTime, Utc};
use service_errors::ServiceError;
use sqlx::{FromRow, PgPool};

use crate::error_mapping;

static SELECT_USER: &str =
    "SELECT * FROM users WHERE email = $1 AND password = crypt($2, password);";

static INSERT_USER: &str =
    "INSERT INTO users (email, password, registration_date) VALUES ($1, crypt($2, gen_salt('bf')), NOW());";

#[derive(Debug, FromRow)]
pub struct User {
    user_id: i32,
    email: String,
    password: String,
    registration_date: DateTime<Utc>,
}

impl User {
    pub async fn register_user(
        connection: &PgPool,
        email: &String,
        password: &String,
    ) -> Result<sqlx::postgres::PgDone, ServiceError> {
        sqlx::query(INSERT_USER)
            .bind(email)
            .bind(password)
            .execute(connection)
            .await
            .map_err(|e| error_mapping::user_registration_error(e, email))
    }

    pub async fn look_up_user(
        connection: &PgPool,
        email: &String,
        password: &String,
    ) -> Result<User, ServiceError> {
        sqlx::query_as::<_, User>(SELECT_USER)
            .bind(email)
            .bind(password)
            .fetch_one(connection)
            .await
            .map_err(|e| error_mapping::user_lookup_error(e, email))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::create_db_pool;

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    async fn connect_register_lookup() {
        let email = format!("{}@test.de", Utc::now()).replace(" ", "_");
        let password = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &email, &password).await.is_ok());
        assert!(User::look_up_user(&pool, &email, &password).await.is_ok());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    async fn register_twice() {
        let email = format!("{}@test.de", Utc::now()).replace(" ", "");
        let password = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &email, &password).await.is_ok());
        assert!(User::register_user(&pool, &email, &password).await.is_err());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    async fn lookup_non_existing_user() {
        let email = "000000000000000000".to_string();
        let password = "000000000000000000".to_string();

        let pool = create_db_pool().await.unwrap();

        assert!(User::look_up_user(&pool, &email, &password).await.is_err());
    }
}