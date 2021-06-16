use actix_session::Session;
use database_integration::user::User;
use middleware::UserDetails;

use actix_web::{
    http::header,
    web::{Data, Form},
    HttpResponse, Responder, Result,
};
use askama::Template;
use rand::RngCore;
use serde::Deserialize;
use sqlx::PgPool;

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

struct Page {
    title: &'static str,
    path: &'static str,
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPage {
    title: &'static str,
    pages: &'static [Page],
    user: Option<User>,
}

impl Default for StatusPage {
    fn default() -> Self {
        StatusPage {
            title: "Status",
            pages: PAGES,
            user: None,
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    title: &'static str,
    pages: &'static [Page],
    error: bool,
}

impl Default for LoginPage {
    fn default() -> Self {
        LoginPage {
            title: "Login",
            pages: PAGES,
            error: false,
        }
    }
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage {
    title: &'static str,
    pages: &'static [Page],
    message: Option<Result<(), &'static str>>,
}

impl Default for RegisterPage {
    fn default() -> Self {
        RegisterPage {
            title: "Register",
            pages: PAGES,
            message: None,
        }
    }
}

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
    pool: Data<sqlx::Pool<sqlx::Postgres>>,
) -> impl Responder {
    let username = form.username.to_lowercase();

    let message = if !username.chars().all(|c| char::is_ascii_alphanumeric(&c)) {
        Err("username must be alphanumeric")
    } else if form.password.chars().count() < 12 || form.password.chars().count() > 256 {
        Err("password must be 12 or more and 256 or less characters in length")
    } else {
        User::register_user(&pool, &username, &form.password)
            .await
            .map(|_| ())
            .map_err(|_| "registration failed")
    };

    RegisterPage {
        message: Some(message),
        ..Default::default()
    }
}

pub async fn login_page() -> impl Responder {
    LoginPage::default()
}

async fn todo_login(
    username: impl AsRef<str>,
    password: impl AsRef<str>,
    session: Session,
    pool: &PgPool,
) -> Result<User, &'static str> {
    // https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#user-ids
    let username = username.as_ref().to_lowercase();

    let user = User::look_up_user(&pool, &username, password.as_ref())
        .await
        .map_err(|_| "Invalid username or password")?;

    // Use 256 bit length for the session ID. This is double of the minimum required by OWASP.
    let mut key = [0u8; 32];
    // ThreadRng uses a CSPRNG as per
    // https://rust-random.github.io/rand/rand/rngs/index.html#our-generators
    rand::thread_rng().fill_bytes(&mut key);
    let session_id = base64::encode(key);

    User::store_session(&pool, &user, &session_id)
        .await
        .map_err(|_| "Database failed")?;
    session
        .set("id", session_id)
        .map_err(|_| "session set failed")?;

    Ok(user)
}

pub async fn do_login(
    form: Form<Credentials>,
    session: Session,
    pool: Data<sqlx::Pool<sqlx::Postgres>>,
) -> impl Responder {
    match todo_login(&form.username, &form.password, session, &pool).await {
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

pub async fn do_logout(session: Session, pool: Data<sqlx::Pool<sqlx::Postgres>>) -> impl Responder {
    // Remove database session if it is shipped in the cookie.
    if let Ok(Some(session_id)) = session.get::<String>("id") {
        User::remove_session(&pool, &session_id).await;
    }
    // Purge the cookie
    session.purge();

    HttpResponse::Found()
        .header(header::LOCATION, "/login")
        .finish()
}

pub async fn status_page(user: Option<UserDetails<User>>) -> impl Responder {
    StatusPage {
        user: user.map(|u| u.0),
        ..Default::default()
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
