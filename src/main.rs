mod configuration;
mod routes;

use actix_web::{App, HttpServer};

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

    HttpServer::new(|| {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .configure(configuration::public_config)
            .configure(configuration::user_config)
            .configure(configuration::admin_config)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
