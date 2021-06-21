use access_control::User as UserTrait;
use chrono::{DateTime, Utc};
use service_errors::ServiceError;
use sqlx::{FromRow, PgPool};
use std::cmp::PartialEq;
use std::collections::HashSet;

/// This constant describes the query to select a [`DbUser`] by their username.
const SELECT_USER: &str = "SELECT * FROM users WHERE username = $1;";

const SELECT_USER_BY_SESSION_ID: &str =
    "SELECT * FROM users WHERE user_id = (SELECT user_id FROM sessions WHERE session_id = $1 AND expiration_date > NOW());";

/// This constant describes the query to insert a new [`DbUser`] by their name and password hash.
/// The registration_date that is part of the [`DbUser`] is set to the current time using postgres' NOW() function.
/// The password hash comes from the access control library and contains the PHC hash.
const INSERT_USER: &str =
    "INSERT INTO users (username, password_hash, registration_date) VALUES ($1, $2, NOW());";

/// The [`INSERT_SESSION`] constant describes the query to insert a session by providing a `session_id` and `user_id`.
///
/// The sessions expiration date is set to the current time plus 5 minutes.
const INSERT_SESSION: &str =
    "INSERT INTO sessions (session_id, user_id, expiration_date) VALUES ($1, $2, NOW() + INTERVAL '5 minutes');";

/// The [`DELETE_SESSION`] constant describes the query to delete a session by its `session_id`.
const DELETE_SESSION: &str = "DELETE FROM sessions WHERE session_id = $1;";

/// The [`SELECT_CAPABILITIES`] constant describes the query to select a new [`DbCapability`] by `user_id`.
const SELECT_CAPABILITIES: &str = "SELECT * FROM capabilities WHERE user_id = $1;";

/// The [`User`] struct is provided to the Middleware is fetched from the database by running [`User::look_up_user`].
///
/// The struct contains only the necessary information to the middleware and skips internal data like the password hash.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    user_id: i32,
    pub username: String,
    password_hash: String,
    pub registration_date: DateTime<Utc>,
    pub capabilities: HashSet<String>,
}

impl UserTrait for User {
    fn username(&self) -> &str {
        &self.username
    }

    fn password_hash(&self) -> &str {
        &self.password_hash
    }

    fn capabilities(&self) -> &HashSet<String> {
        &self.capabilities
    }
}

/// The [`DbUser`] struct represents the users table in the database.
/// It is only used to build a [`User`] by combining its information with [`DbCapability`].
///
/// The query to select a [`DbUser`] is represented by the constant `SELECT_USER` and used in [`User::look_up_user`].
///
/// # Table structure
/// ``` sql
/// CREATE TABLE IF NOT EXISTS users (
///   user_id SERIAL PRIMARY KEY,
///   username TEXT NOT NULL UNIQUE,
///   password_hash TEXT NOT NULL,
///   registration_date TIMESTAMPTZ NOT NULL
/// );
/// ```
#[derive(Debug, Clone, FromRow)]
struct DbUser {
    user_id: i32,
    username: String,
    password_hash: String,
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
    /// Tries to insert a new user into the database by running the `INSERT_USER` query.
    ///
    ///
    /// The query may fail if the connection to postgres is down or the user already exists.
    /// In this case a [`ServiceError::UserRegistrationFailed`] is returned.
    ///
    /// If successful, the functions returns [`sqlx::postgres::PgDone`].
    pub(crate) async fn register_user(
        connection: &PgPool,
        username: &str,
        password_hash: &str,
    ) -> Result<(), ServiceError> {
        sqlx::query(INSERT_USER)
            .bind(username)
            .bind(password_hash)
            .execute(connection)
            .await
            .map_err(|_| Self::user_registration_error(username))?;
        Ok(())
    }

    /// Tries to look up a [`User`] by running the `SELECT_USER` and `SELECT_CAPABILITIES` query.
    ///
    /// The [`User`] struct is not a representation of what the user looks like in the database, but what the middleware needs to function.
    ///
    ///
    /// Each query may fail if the connection to postgres is down or the user already exists.
    /// In this case a [`ServiceError::UserNotFound`] or a [`ServiceError::Default`] error is returned, depending on the queries return type.
    ///
    /// If successful, the function return a [`User`] that combines both the `SELECT_USER` and `SELECT_CAPABILITIES` queries, by reading out the necessary data.
    pub(crate) async fn look_up_user(
        connection: &PgPool,
        username: impl AsRef<str>,
    ) -> Result<User, ServiceError> {
        let username = username.as_ref();

        let dbuser = sqlx::query_as::<_, DbUser>(SELECT_USER)
            .bind(username)
            .fetch_one(connection)
            .await
            .map_err(|e| Self::user_lookup_error(e, username))?;
        let user_caps: HashSet<String> = sqlx::query_as::<_, DbCapability>(SELECT_CAPABILITIES)
            .bind(dbuser.user_id)
            .fetch_all(connection)
            .await
            .map_err(|e| Self::user_lookup_error(e, username))?
            .into_iter()
            .map(|c: DbCapability| c.label)
            .collect();

        Ok(User {
            user_id: dbuser.user_id,
            username: dbuser.username,
            password_hash: dbuser.password_hash,
            registration_date: dbuser.registration_date,
            capabilities: user_caps,
        })
    }

    /// Tries to retrieve a [`User`] by `session_id`.
    ///
    /// The [`User`] struct is not a representation of what the user looks like in the database, but what the middleware needs to function.
    ///
    ///
    /// On failure, the function returns a [`ServiceError`].
    /// An error occurs then the user or their capabilities cannot be found in the database.
    ///
    /// If successful, the function return a [`User`] struct that combines the necessary data from two requests.
    pub(crate) async fn look_up_user_from_session(
        connection: &PgPool,
        session_id: &str,
    ) -> Result<User, ServiceError> {
        let dbuser = sqlx::query_as::<_, DbUser>(SELECT_USER_BY_SESSION_ID)
            .bind(session_id)
            .fetch_one(connection)
            .await
            .map_err(|e| Self::user_lookup_error(e, session_id))?;
        let user_caps: HashSet<String> = sqlx::query_as::<_, DbCapability>(SELECT_CAPABILITIES)
            .bind(dbuser.user_id)
            .fetch_all(connection)
            .await
            .map_err(|e| Self::user_lookup_error(e, session_id))?
            .into_iter()
            .map(|c: DbCapability| c.label)
            .collect();

        Ok(User {
            user_id: dbuser.user_id,
            username: dbuser.username,
            password_hash: dbuser.password_hash,
            registration_date: dbuser.registration_date,
            capabilities: user_caps,
        })
    }

    /// Tries to insert a new session into the database.
    ///
    /// This query may fail if the selected `session_id` is already in the sessions table.
    /// If successful, the query returns `()`.
    ///
    /// A session has the following format PostgreSql:
    /// ```sql
    /// TABLE sessions (
    ///   session_id TEXT PRIMARY KEY,
    ///   user_id SERIAL,
    ///   expiration_date TIMESTAMPTZ NOT NULL,
    ///   CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(user_id)
    /// );
    /// ```
    pub(crate) async fn store_session(
        connection: &PgPool,
        user: &User,
        session_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(INSERT_SESSION)
            .bind(session_id)
            .bind(user.user_id)
            .execute(connection)
            .await?;
        Ok(())
    }

    /// Tries to delete a session by its `session_id`.
    ///
    /// This query may fail if the `session_id` does not exist.
    /// If successful, the function returns `()`.
    pub(crate) async fn remove_session(
        connection: &PgPool,
        session_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(DELETE_SESSION)
            .bind(session_id)
            .execute(connection)
            .await?;
        Ok(())
    }

    /// Map a [`sqlx::Error`] to a [`ServiceError`] when a user lookup fails.
    ///
    /// As a default, [`ServiceError::Default`] is returned.
    /// If the [`sqlx::Error`] is [`sqlx::Error::RowNotFound`], [`ServiceError::UserNotFound`] is returned.
    fn user_lookup_error(error: sqlx::Error, username: &str) -> ServiceError {
        match error {
            sqlx::Error::RowNotFound => ServiceError::UserNotFound {
                username: username.into(),
            },
            _ => ServiceError::Default,
        }
    }

    /// Map a [`sqlx::Error`] to a [`ServiceError`] when a user lookup fails.
    ///
    /// Currently, only [`ServiceError::UserRegistrationFailed`] is returned.
    fn user_registration_error(username: &str) -> ServiceError {
        ServiceError::UserRegistrationFailed {
            username: username.into(),
        }
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
        let username = format!("{}_register_lookup", Utc::now()).replace(" ", "_");
        let password_hash = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &username, &password_hash)
            .await
            .is_ok());
        let user_lookup = User::look_up_user(&pool, &username).await.unwrap();

        assert_eq!(user_lookup.username, username);
        assert_eq!(user_lookup.capabilities, HashSet::new());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    /// Makes sure a user cannot register itself twice.
    async fn register_twice() {
        let username = format!("{}_register_twice", Utc::now()).replace(" ", "");
        let password_hash = format!("{}", Utc::now());

        let pool = create_db_pool().await.unwrap();

        assert!(User::register_user(&pool, &username, &password_hash)
            .await
            .is_ok());
        assert!(User::register_user(&pool, &username, &password_hash)
            .await
            .is_err());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    /// Tries to look up a user that does not exist.
    async fn lookup_non_existing_user() {
        let username: String = (0..20).map(|_| "no").collect();
        let pool = create_db_pool().await.unwrap();

        assert!(User::look_up_user(&pool, &username).await.is_err());
    }

    #[ignore = "Needs database to run"]
    #[actix_rt::test]
    /// Tries to insert, lookup and delete a session from the database.
    async fn insert_lookup_delete_session() {
        let username = format!("{}_session_test", Utc::now()).replace(" ", "");
        let password_hash = format!("{}", Utc::now());
        let pool = create_db_pool().await.unwrap();
        let session_id = format!("{}_session_id", Utc::now()).replace(" ", "");

        User::register_user(&pool, &username, &password_hash)
            .await
            .unwrap();
        let user = User::look_up_user(&pool, &username).await.unwrap();

        User::store_session(&pool, &user, session_id.as_str())
            .await
            .unwrap();

        let retrieved_user = User::look_up_user_from_session(&pool, session_id.as_str())
            .await
            .unwrap();

        assert_eq!(user, retrieved_user);

        User::remove_session(&pool, session_id.as_str())
            .await
            .unwrap();
    }
}
