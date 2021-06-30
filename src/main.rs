use std::{env, fs::File, io::BufReader};

use database_integration::utility::create_db_pool;

use actix_web::{
    http::{self, header},
    middleware::{self, errhandlers::ErrorHandlers},
    App, HttpServer,
};
use rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    NoClientAuth, ServerConfig,
};

mod configuration;
mod pages;
mod routes;

/// Error message shown if the certificate file in missing
const CERT_ERROR_MESSAGE: &str = "Could not find './cert.pem'";
/// Error message shown if the key file is missing
const KEY_ERROR_MESSAGE: &str = "Could not find './key.pem'";

/// Content Security Policy for the service.
///
/// Currently this uses the tightened basic CSP policy from the [OWASP
/// Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) with allowance
/// for the jsdelivr.com CDN.
const CSP_CONFIG: &str = "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; img-src 'self'; style-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'self'; form-action 'self';";

/// Builds the service address by retrieving the values of the `SERVICE_DOMAIN` and `SERVICE_PORT` environment variables.
///
/// This function calls **`.expect`**.
/// This is mostly to avoid situations in which the service should not run with default values.
/// In every other situation this shouldn't be an issue, thanks to the `.env` file.
fn build_address() -> String {
    let domain = env::var("SERVICE_DOMAIN").expect("SERVICE_DOMAIN not set");
    let port = env::var("SERVICE_PORT").expect("SERVICE_PORT not set");
    format!("{}:{}", domain, port)
}

/// This Service starts the actix-web example application.
///
/// To execute this program with its default values, execute these commands.
///
/// 1. `./automation.sh container start`
/// 2. `./automation.sh db up`
/// 3. `./automation gencert`
/// 4. `cargo build --workspace`
/// 5. `cargo run`
/// 6. Visit [https://localhost:8080/](https://localhost:8080/)
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();

    let pool = create_db_pool()
        .await
        .expect("could not create database pool");

    // Load TLS certificates
    let mut config = ServerConfig::new(NoClientAuth::new());
    let cert_file = &mut BufReader::new(File::open("cert.pem").expect(CERT_ERROR_MESSAGE));
    let key_file = &mut BufReader::new(File::open("key.pem").expect(KEY_ERROR_MESSAGE));
    let cert_chain = certs(cert_file).unwrap();
    let mut keys = pkcs8_private_keys(key_file).unwrap();
    config.set_single_cert(cert_chain, keys.remove(0)).unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(
                middleware::DefaultHeaders::new()
                    .header(header::CONTENT_SECURITY_POLICY, CSP_CONFIG),
            )
            .wrap(
                ErrorHandlers::new()
                    .handler(http::StatusCode::UNAUTHORIZED, routes::login_redirect),
            )
            .wrap(actix_web::middleware::Logger::default())
            .configure(|c| configuration::website(c, &pool))
            .configure(|c| configuration::user_config(c, &pool))
            .configure(|c| configuration::admin_config(c, &pool))
    })
    .bind_rustls(build_address().as_str(), config)?
    .run()
    .await
}

// ----------------------------------------------------------------------------
// integration tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // These test should be rewritten and either build using a macro or a combination of functions.
    // Time limitation don't allow for this (currently), keep in mind that the tests are very repetitive.
    use super::*;
    use actix_web::{cookie::Cookie, test, App};
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    use serde::Serialize;
    use sqlx::{postgres::PgRow, Row};

    #[derive(Serialize)]
    struct Credentials {
        username: String,
        password: String,
    }

    #[ignore = "Database necessary to run these tests"]
    #[actix_rt::test]
    async fn register_login_info_logout() {
        dotenv::dotenv().ok();
        // create database pool
        let pool = create_db_pool()
            .await
            .expect("could not create database pool");

        // Create app with standard configuration
        let mut app = test::init_service(
            App::new()
                .configure(|c| configuration::website(c, &pool))
                .configure(|c| configuration::user_config(c, &pool))
                .configure(|c| configuration::admin_config(c, &pool)),
        )
        .await;

        // Tests start here
        let credentials = Credentials {
            username: std::str::from_utf8(
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(32)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .to_string()
            .to_lowercase(),
            password: "12345678901234567890".to_string(),
        };

        // register user
        let register_req = test::TestRequest::post()
            .set_form(&credentials)
            .uri("/register")
            .to_request();
        let resp = test::call_service(&mut app, register_req).await;
        assert!(resp.status().is_success());

        // check that the database contains the newly created user
        let user_id: i32 = sqlx::query("SELECT * FROM users WHERE username = $1;")
            .bind(&credentials.username)
            .map(|row: PgRow| row.try_get("user_id").unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        // login user
        let login_req = test::TestRequest::post()
            .set_form(&credentials)
            .uri("/login")
            .to_request();
        let resp = test::call_service(&mut app, login_req).await;
        assert!(resp.status().is_redirection());

        // check that the session has been created successfully
        sqlx::query("SELECT * FROM sessions WHERE user_id = $1;")
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .unwrap();

        // get user information
        let id_cookie = resp
            .response()
            .cookies()
            .filter(|c| c.name() == "id")
            .collect::<Vec<Cookie>>()
            .get(0)
            .unwrap()
            .to_owned();

        // lookup user information page
        let info_req = test::TestRequest::get()
            .cookie(id_cookie.clone())
            .uri("/")
            .to_request();
        let resp = test::call_service(&mut app, info_req).await;
        assert!(resp.status().is_success());

        // logout user
        let info_req = test::TestRequest::post()
            .cookie(id_cookie)
            .uri("/logout")
            .to_request();
        let resp = test::call_service(&mut app, info_req).await;
        assert!(resp.status().is_redirection());

        // check that the session has been deleted successfully
        assert!(sqlx::query("SELECT * FROM sessions WHERE user_id = $1;")
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .is_err());
    }

    #[ignore = "Database necessary to run these tests"]
    #[actix_rt::test]
    #[should_panic]
    async fn registration_password_to_short() {
        dotenv::dotenv().ok();
        // create database pool
        let pool = create_db_pool()
            .await
            .expect("could not create database pool");

        // Create app with standard configuration
        let mut app = test::init_service(
            App::new()
                .configure(|c| configuration::website(c, &pool))
                .configure(|c| configuration::user_config(c, &pool))
                .configure(|c| configuration::admin_config(c, &pool)),
        )
        .await;

        // Tests start here
        let credentials = Credentials {
            username: std::str::from_utf8(
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(32)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .to_string()
            .to_lowercase(),
            password: std::str::from_utf8(
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(11)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .to_string()
            .to_lowercase(),
        };

        // register user
        let register_req = test::TestRequest::post()
            .set_form(&credentials)
            .uri("/register")
            .to_request();
        let resp = test::call_service(&mut app, register_req).await;
        assert!(!resp.status().is_redirection());

        // check that the database contains the newly created user
        let _: i32 = sqlx::query("SELECT * FROM users WHERE username = $1;")
            .bind(&credentials.username)
            .map(|row: PgRow| row.try_get("user_id").unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    }

    #[ignore = "Database necessary to run these tests"]
    #[actix_rt::test]
    #[should_panic]
    async fn registration_password_to_long() {
        dotenv::dotenv().ok();
        // create database pool
        let pool = create_db_pool()
            .await
            .expect("could not create database pool");

        // Create app with standard configuration
        let mut app = test::init_service(
            App::new()
                .configure(|c| configuration::website(c, &pool))
                .configure(|c| configuration::user_config(c, &pool))
                .configure(|c| configuration::admin_config(c, &pool)),
        )
        .await;

        // Tests start here
        let credentials = Credentials {
            username: std::str::from_utf8(
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(32)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .to_string()
            .to_lowercase(),
            password: std::str::from_utf8(
                &thread_rng()
                    .sample_iter(Alphanumeric)
                    .take(257)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .to_string()
            .to_lowercase(),
        };

        // register user
        let register_req = test::TestRequest::post()
            .set_form(&credentials)
            .uri("/register")
            .to_request();
        let resp = test::call_service(&mut app, register_req).await;
        assert!(!resp.status().is_redirection());

        // check that the database contains the newly created user
        let _: i32 = sqlx::query("SELECT * FROM users WHERE username = $1;")
            .bind(&credentials.username)
            .map(|row: PgRow| row.try_get("user_id").unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    }
}
