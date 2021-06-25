use std::{collections::HashSet, fmt};

use crate::routes;
use database_integration::PostgreSqlBackend;
use middleware::RustAuthMiddleware;

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

pub fn website(cfg: &mut web::ServiceConfig, pool: &Pool<Postgres>) {
    let backend = PostgreSqlBackend::new(pool.clone());

    // Register
    cfg.service(
        resource("/register")
            .wrap(RustAuthMiddleware::new(backend.clone(), HashSet::new()))
            .route(web::get().to(routes::register_page))
            .route(web::post().to(routes::do_register)),
    );

    // Login
    cfg.service(
        resource("/login")
            .wrap(RustAuthMiddleware::new(backend.clone(), HashSet::new()))
            .route(web::get().to(routes::login_page))
            .route(web::post().to(routes::do_login)),
    );

    // Logout
    cfg.service(
        resource("/logout")
            .wrap(RustAuthMiddleware::new(backend.clone(), HashSet::new()))
            .route(web::post().to(routes::do_logout)),
    );

    // Status
    cfg.service(
        resource("/")
            .wrap(RustAuthMiddleware::new(backend, HashSet::new()))
            .route(web::get().to(routes::status_page)),
    );
}

pub fn user_config(cfg: &mut web::ServiceConfig, pool: &Pool<Postgres>) {
    cfg.service(
        resource("/information/user")
            .wrap(RustAuthMiddleware::new(
                PostgreSqlBackend::new(pool.clone()),
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
            .wrap(RustAuthMiddleware::new(
                PostgreSqlBackend::new(pool.clone()),
                [Capabilities::AdminRead]
                    .iter()
                    .map(|c| c.to_string())
                    .collect(),
            ))
            .route(get().to(routes::retrieve_admin_information)),
    );
}
