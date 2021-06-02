use actix_web::{
    web::{get, resource},
    App, HttpServer, Result,
};
use authorization::SimpleStringMiddleware;
use authorization::UserDetails;

/// This Service starts an HttpServer using actix-web with four routes.
/// - A route that serves mocked public information under /information/public
/// - A route that serves mocked user specific information under /information/user
/// - A route that serves mocked admin specific information under /information/admin
///
/// The Authorization header must be set to either User or Admin to access 'sensitive data'
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    println!("{:?}", std::env::var("DATABASE_URL"));
    println!("{}", service_errors::ServiceError::Default);

    HttpServer::new(|| {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .service(
                resource("/information/admin")
                    .wrap(SimpleStringMiddleware {
                        permission: "Admin".to_string(),
                    })
                    .route(get().to(retrieve_admin_information)),
            )
            .service(resource("/information/public").route(get().to(retrieve_public_information)))
            .service(
                resource("/information/user")
                    .wrap(SimpleStringMiddleware {
                        permission: "User".to_string(),
                    })
                    .route(get().to(retrieve_user_information)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

/// Used to access public information
async fn retrieve_public_information() -> Result<String> {
    Ok("public information".to_string())
}

/// Used to access mocked user-specific information
async fn retrieve_user_information() -> Result<String> {
    Ok("user information".to_string())
}

/// Used to access mocked admin-specific information
async fn retrieve_admin_information(user: UserDetails) -> Result<String> {
    Ok(format!("{:?}", user.0))
}
