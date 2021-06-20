use std::{fs::File, io::BufReader};

use database_integration::utility::create_db_pool;

use actix_web::{App, HttpServer};
use rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    NoClientAuth, ServerConfig,
};

mod configuration;
mod pages;
mod routes;

const CERT_ERROR_MESSAGE: &str = "Could not find './cert.pem'";
const KEY_ERROR_MESSAGE: &str = "Could not find './key.pem'";

/// This Service starts an HttpServer using actix-web with four routes.
/// - A route that serves mocked public information under /information/public
/// - A route that serves mocked user specific information under /information/user
/// - A route that serves mocked admin specific information under /information/admin
///
/// The Authorization header must be set to either User or Admin to access 'sensitive data'
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
            .wrap(actix_web::middleware::Logger::default())
            .configure(|c| configuration::website(c, &pool))
            .configure(|c| configuration::user_config(c, &pool))
            .configure(|c| configuration::admin_config(c, &pool))
    })
    .bind_rustls("127.0.0.1:8080", config)?
    .run()
    .await
}
