use crate::pages::{LoginPage, RegisterPage, StatusPage};

use database_integration::{user::User, PostgreSqlBackend};
use middleware::{SessionState, UserDetails};

use actix_web::{http::header, web::Form, HttpResponse, Responder, Result};
use askama::Template;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

pub async fn register_page() -> impl Responder {
    RegisterPage::default()
}

pub async fn do_register(
    form: Form<Credentials>,
    session_state: SessionState<PostgreSqlBackend, User>,
) -> impl Responder {
    let message = session_state
        .register(&form.username, &form.password)
        .await
        .map_err(|_| "registration failed");
    RegisterPage {
        message: Some(message),
        ..Default::default()
    }
}

pub async fn login_page() -> impl Responder {
    LoginPage::default()
}

pub async fn do_login(
    form: Form<Credentials>,
    session_state: SessionState<PostgreSqlBackend, User>,
) -> impl Responder {
    match session_state.login(&form.username, &form.password).await {
        Ok(_) => HttpResponse::Found().header(header::LOCATION, "/").finish(),
        Err(_) => HttpResponse::Ok().body(
            LoginPage {
                error: true,
                ..Default::default()
            }
            .render()
            .unwrap(),
        ),
    }
}

pub async fn do_logout(session_state: SessionState<PostgreSqlBackend, User>) -> impl Responder {
    session_state.logout().await;
    HttpResponse::Found()
        .header(header::LOCATION, "/login")
        .finish()
}

pub async fn status_page(user_details: UserDetails<PostgreSqlBackend, User>) -> impl Responder {
    StatusPage {
        user: Some(user_details.user),
        ..Default::default()
    }
}

/// Used to access mocked user-specific information
pub async fn retrieve_user_information(
    user_details: UserDetails<PostgreSqlBackend, User>,
) -> Result<String> {
    Ok(format!("User information: {:?}", user_details.user))
}

/// Used to access mocked admin-specific information
pub async fn retrieve_admin_information(
    user_details: UserDetails<PostgreSqlBackend, User>,
) -> Result<String> {
    Ok(format!("Admin information: {:?}", user_details.user))
}
