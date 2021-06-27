use askama::Template;
use database_integration::user::User;

/// A collection of the available pages that are displayed in the nav-bar.
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

/// Every page that is used in the example website is represented inside the [`Page`] struct.
///
/// The [`Page`] struct represents the Page as a title in the nav-bar and a path under which the page can be found.
pub struct Page {
    title: &'static str,
    path: &'static str,
}

/// The [`StatusPage`] struct represents the default landing page and displays the available user data (if available).
/// # Traits
/// The [`StatusPage`] struct implements the [`Default`] trait.
/// It can therefore be used by only defining the User data or using the default value of `None` if the user is not logged in.
///
/// Additionally the [`StatusPage`] struct uses the [`askama::Template`] at `template/status.html` and `askama_actix` to build a HTTP response.
/// # Example usage
/// ```
/// # use database_integration::{user::User, PostgreSqlBackend};
/// # use actix_web::Responder;
/// pub async fn status_page(user_details: UserDetails<PostgreSqlBackend, User>) -> impl Responder {
///     StatusPage {
///         user: Some(user_details.user),
///         ..Default::default()
///     }
/// }
/// ```
#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusPage {
    pub title: &'static str,
    pub pages: &'static [Page],
    pub user: Option<User>,
}

impl Default for StatusPage {
    /// Implementation of the [`Default`] trait for the [`StatusPage`] struct.
    ///
    /// # Default Values
    /// ```
    /// StatusPage {
    ///     title: "Status",
    ///     pages: PAGES,
    ///     user: None,
    /// }
    /// ```
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
pub struct LoginPage {
    pub title: &'static str,
    pub pages: &'static [Page],
    pub error: bool,
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
pub struct RegisterPage {
    pub title: &'static str,
    pub pages: &'static [Page],
    pub message: Option<Result<(), &'static str>>,
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
