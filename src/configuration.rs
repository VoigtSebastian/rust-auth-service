use crate::routes;
use actix_web::{
    web,
    web::{get, resource},
};
use authorization::SimpleStringMiddleware;

pub fn public_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        resource("/information/public").route(get().to(routes::retrieve_public_information)),
    );
}

pub fn user_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        resource("/information/user")
            .wrap(SimpleStringMiddleware {
                permission: "User".to_string(),
            })
            .route(get().to(routes::retrieve_user_information)),
    );
}

pub fn admin_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        resource("/information/admin")
            .wrap(SimpleStringMiddleware {
                permission: "Admin".to_string(),
            })
            .route(get().to(routes::retrieve_admin_information)),
    );
}
