use chrono::{DateTime, Utc};
use service_errors::ServiceError;
use sqlx::{FromRow, PgPool};
use std::collections::HashSet;

use crate::error_mapping;

/// This constant describes the query to select a [`DbUser`] by their name and password.
/// ```
/// sqlx::query_as::<_, DbUser>(SELECT_USER)
///     .bind(email)
///     .bind(password)
///     .fetch_one(connection)
///     .await
/// ```
const SELECT_USER: &'static str =
    "SELECT * FROM users WHERE email = $1 AND password = crypt($2, password);";

const SELECT_USER_BY_SESSION_ID: &'static str =
    "SELECT * FROM users WHERE user_id = (SELECT user_id FROM sessions WHERE session_id = $1 AND expiration_date > NOW());";

/// This constant describes the query to insert a new [`DbUser`] by their name and password.
/// The registration_date that is part of the [`DbUser`] is set to the current time using postgres' NOW() function.
/// The password is hashed using postgres' `crypt()` function with `gen_salt('bf')` to generate a blowfish salt.
/// ```
/// sqlx::query(INSERT_USER)
///     .bind(email)
///     .bind(password)
///     .execute(connection)
///     .await
/// ```
const INSERT_USER: &'static str =
    "INSERT INTO users (email, password, registration_date) VALUES ($1, crypt($2, gen_salt('bf')), NOW());";

const INSERT_SESSION: &'static str =
    "INSERT INTO sessions (session_id, user_id, expiration_date) VALUES ($1, $2, NOW() + INTERVAL '5 minutes');";

const DELETE_SESSION: &'static str = "DELETE FROM sessions WHERE session_id = $1;";

/// This constant describes the query to select a new [`DbCapability`] by a `user_id`.
/// ```
/// sqlx::query_as::<_, DbCapability>(SELECT_CAPABILITIES)
///     .bind(user_id)
///     .fetch_all(connection)
///     .await?
///     .into_iter()
///     .collect()
/// ```
const SELECT_CAPABILITIES: &str = "SELECT * FROM capabilities WHERE user_id = $1;";

/// The [`User`] struct is provided to the Middleware is fetched from the database by running [`User::look_up_user`].
///
/// The struct contains only the necessary information to the middleware and skips internal data like the password hash.
#[derive(Debug, Clone)]
pub struct User {
    user_id: i32,
    pub email: String,
    pub registration_date: DateTime<Utc>,
    pub capabilities: HashSet<String>,
}

/// The [`DbUser`] struct represents the users table in the database.
/// It is only used to build a [`User`] by combining its information with [`DbCapability`].
///
/// The query to select a [`DbUser`] is represented by the constant [`SELECT_USER`] and used in [`User::look_up_user`].
///
/// # Table structure
/// ``` sql
/// CREATE TABLE IF NOT EXISTS users (
///   user_id SERIAL PRIMARY KEY,
///   email TEXT NOT NULL UNIQUE,
///   password TEXT NOT NULL,
///   registration_date TIMESTAMPTZ NOT NULL
/// );
/// ```
#[derive(Debug, Clone, FromRow)]
struct DbUser {
    user_id: i32,
    email: String,
    password: String,
    registration_date: DateTime<Utc>,
}

/// The [`DbCapability`] struct represents the capability table in the database.
/// It is only used to query the necessary information to build a [`User`] by combining it with a [`DbUser`].
///
/// # Table structure
/// ``` sql
/// TABLE capabilities (
///   label TEXT NOT NULL,
///   user_id SERIAL,
///   CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(user_id),
///   UNIQUE (label, user_id)
/// );
/// ```
#[derive(Debug, Clone, FromRow)]
struct DbCapability {
    user_id: i32,
    label: String,
}

impl User {
    /// Tries to insert a new user into the database by running the [`INSERT_USER`] query.
    ///
    /// # Returns
    /// The query may fail if the connection to postgres is down or the user already exists.
    /// In this case a [`ServiceError::UserRegistrationFailed`] is returned.
    ///
    /// If successful, the functions returns [`sqlx::postgres::PgDone`].
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

    /// Tries to look up a [`User`] by running the [`SELECT_USER`] and [`SELECT_CAPABILITIES`] query.
    ///
    /// The [`User`] struct is not a representation of what the user looks like in the database, but what the middleware needs to function.
    ///
    /// # Returns
    /// Each query may fail if the connection to postgres is down or the user already exists.
    /// In this case a [`ServiceError::UserNotFound`] or a [`ServiceError::Default`] error is returned, depending on the queries return type.
    ///
    /// If successful, the function return a [`User`] that combines both the [`SELECT_USER`] and [`SELECT_CAPABILITIES`] queries, by reading out the necessary data.
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
    /// Tries to register and look up a user by running [`User::register_user`] and [`User::look_up_user`].
    async fn connect_register_lookup() {
        let email = format!("{}@test.de", Utc::now()).replace(" ", "_");
        let password = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &email, &password).await.is_ok());
        let user_lookup = User::look_up_user(&pool, &email, &password).await.unwrap();

        assert_eq!(user_lookup.email, email);
        assert_eq!(user_lookup.capabilities, HashSet::new());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    /// Makes sure a user cannot register itself twice.
    async fn register_twice() {
        let email = format!("{}@test.de", Utc::now()).replace(" ", "");
        let password = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &email, &password).await.is_ok());
        assert!(User::register_user(&pool, &email, &password).await.is_err());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    /// Tries to look up a user that does not exist.
    async fn lookup_non_existing_user() {
        let email = "000000000000000000".to_string();
        let password = "000000000000000000".to_string();

        let pool = create_db_pool().await.unwrap();

        assert!(User::look_up_user(&pool, &email, &password).await.is_err());
    }
}
