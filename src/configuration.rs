use std::fmt;

use crate::routes;
use authorization::SimpleStringMiddleware;
use database_integration::PostgreSqlBackend;

use actix_web::{
    web,
    web::{get, resource},
};
use sqlx::{Pool, Postgres};

pub fn public_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        resource("/information/public").route(get().to(routes::retrieve_public_information)),
    );
}

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
