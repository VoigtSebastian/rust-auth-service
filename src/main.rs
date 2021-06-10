use actix_web::{App, HttpServer};
use database_integration::utility::create_db_pool;

mod configuration;
mod routes;

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

    HttpServer::new(move || {
        App::new()
            // Store database pool in the application data to have it available in requests
            .data(pool.clone())
            .wrap(actix_web::middleware::Logger::default())
            .configure(configuration::website)
            .configure(|c| configuration::user_config(c, &pool))
            .configure(|c| configuration::admin_config(c, &pool))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
