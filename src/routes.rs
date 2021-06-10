use database_integration::user::User;
use middleware::UserDetails;

use actix_web::{Responder, Result};
use askama::Template;

struct Page {
    title: &'static str,
    path: &'static str,
}

const PAGES: &[Page] = &[
    Page {
        title: "Status",
        path: "/",
    },
    Page {
        title: "Login",
        path: "/login",
    },
    Page {
        title: "Register",
        path: "/register",
    },
];

#[derive(Template)]
#[template(path = "status.html")]
struct Status {
    title: &'static str,
    pages: &'static [Page],
    user: Option<User>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct Login {
    title: &'static str,
    pages: &'static [Page],
}

#[derive(Template)]
#[template(path = "register.html")]
struct Register {
    title: &'static str,
    pages: &'static [Page],
}

pub async fn status_page(user: Option<UserDetails<User>>) -> impl Responder {
    // Debug
    // let user = User {
    //     email: "user@example.com".to_string(),
    //     registration_date: Utc::now(),
    //     capabilities: ["UserRead", "Comment"]
    //         .iter()
    //         .map(|s| s.to_string())
    //         .collect(),
    // };
    // Status { user: Some(user) }

    Status {
        title: "Status",
        pages: PAGES,
        user: user.map(|u| u.0),
    }
}

pub async fn login_page() -> impl Responder {
    Login {
        title: "Login",
        pages: PAGES,
    }
}

pub async fn register_page() -> impl Responder {
    Register {
        title: "Register",
        pages: PAGES,
    }
}

/// Used to access mocked user-specific information
pub async fn retrieve_user_information(user: UserDetails<User>) -> Result<String> {
    Ok(format!("User information: {:?}", user.0))
}

/// Used to access mocked admin-specific information
pub async fn retrieve_admin_information(user: UserDetails<User>) -> Result<String> {
    Ok(format!("Admin information: {:?}", user.0))
}
