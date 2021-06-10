use std::fmt;

use crate::routes;
use database_integration::PostgreSqlBackend;
use middleware::SimpleStringMiddleware;

use actix_web::{
    web,
    web::{get, resource},
};
use sqlx::{Pool, Postgres};

#[derive(Debug)]
pub enum Capabilities {
    UserRead,
    AdminRead,
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub fn website(cfg: &mut web::ServiceConfig) {
    cfg.service(resource("/").route(web::get().to(routes::status_page)));
    cfg.service(resource("/login").route(web::get().to(routes::login_page)));
    cfg.service(resource("/register").route(web::get().to(routes::register_page)));
}

pub fn user_config(cfg: &mut web::ServiceConfig, pool: &Pool<Postgres>) {
    cfg.service(
        resource("/information/user")
            .wrap(SimpleStringMiddleware::new(
                PostgreSqlBackend { db: pool.clone() },
                [Capabilities::UserRead]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            ))
            .route(get().to(routes::retrieve_user_information)),
    );
}

pub fn admin_config(cfg: &mut web::ServiceConfig, pool: &Pool<Postgres>) {
    cfg.service(
        resource("/information/admin")
            .wrap(SimpleStringMiddleware::new(
                PostgreSqlBackend { db: pool.clone() },
                [Capabilities::AdminRead]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            ))
            .route(get().to(routes::retrieve_admin_information)),
    );
}
