use std::collections::HashSet;

use chrono::{DateTime, Utc};
use service_errors::ServiceError;
use sqlx::{FromRow, PgPool};

use crate::error_mapping;

const SELECT_USER: &'static str =
    "SELECT * FROM users WHERE email = $1 AND password = crypt($2, password);";

const SELECT_USER_BY_SESSION_ID: &'static str =
    "SELECT * FROM users WHERE user_id = (SELECT user_id FROM sessions WHERE session_id = $1 AND expiration_date > NOW());";

const INSERT_USER: &'static str =
    "INSERT INTO users (email, password, registration_date) VALUES ($1, crypt($2, gen_salt('bf')), NOW());";

const INSERT_SESSION: &'static str =
    "INSERT INTO sessions (session_id, user_id, expiration_date) VALUES ($1, $2, NOW() + INTERVAL '5 minutes');";

const DELETE_SESSION: &'static str = "DELETE FROM sessions WHERE session_id = $1;";

const SELECT_CAPABILITIES: &str = "SELECT * FROM capabilities WHERE user_id = $1;";

#[derive(Debug, Clone)]
pub struct User {
    user_id: i32,
    pub email: String,
    pub registration_date: DateTime<Utc>,
    pub capabilities: HashSet<String>,
}

#[derive(Debug, Clone, FromRow)]
struct DbUser {
    user_id: i32,
    email: String,
    password: String,
    registration_date: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
struct DbCapability {
    user_id: i32,
    label: String,
}

impl User {
    pub async fn register_user(
        connection: &PgPool,
        email: &str,
        password: &str,
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
        email: &str,
        password: &str,
    ) -> Result<User, ServiceError> {
        let dbuser = sqlx::query_as::<_, DbUser>(SELECT_USER)
            .bind(email)
            .bind(password)
            .fetch_one(connection)
            .await
            .map_err(|e| error_mapping::user_lookup_error(e, email))?;
        let user_caps: HashSet<String> = sqlx::query_as::<_, DbCapability>(SELECT_CAPABILITIES)
            .bind(dbuser.user_id)
            .fetch_all(connection)
            .await
            .map_err(|e| error_mapping::user_lookup_error(e, email))?
            .into_iter()
            .map(|c: DbCapability| c.label)
            .collect();

        Ok(User {
            user_id: dbuser.user_id,
            email: dbuser.email,
            registration_date: dbuser.registration_date,
            capabilities: user_caps,
        })
    }

    pub async fn look_up_user_from_session(
        connection: &PgPool,
        session_id: &str,
    ) -> Result<User, ServiceError> {
        let dbuser = sqlx::query_as::<_, DbUser>(SELECT_USER_BY_SESSION_ID)
            .bind(session_id)
            .fetch_one(connection)
            .await
            .map_err(|e| error_mapping::user_lookup_error(e, session_id))?;
        let user_caps: HashSet<String> = sqlx::query_as::<_, DbCapability>(SELECT_CAPABILITIES)
            .bind(dbuser.user_id)
            .fetch_all(connection)
            .await
            .map_err(|e| error_mapping::user_lookup_error(e, session_id))?
            .into_iter()
            .map(|c: DbCapability| c.label)
            .collect();

        Ok(User {
            user_id: dbuser.user_id,
            email: dbuser.email,
            registration_date: dbuser.registration_date,
            capabilities: user_caps,
        })
    }

    pub async fn store_session(
        connection: &PgPool,
        user: &User,
        session_id: &str,
    ) -> Result<(), ServiceError> {
        sqlx::query(INSERT_SESSION)
            .bind(session_id)
            .bind(user.user_id)
            .execute(connection)
            .await
            .unwrap();
        Ok(())
    }

    pub async fn remove_session(connection: &PgPool, session_id: &str) {
        sqlx::query(DELETE_SESSION)
            .bind(session_id)
            .execute(connection)
            .await
            .expect("database failed");
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
