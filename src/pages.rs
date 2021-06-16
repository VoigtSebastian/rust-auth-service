use database_integration::user::User;

use askama::Template;

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

pub struct Page {
    title: &'static str,
    path: &'static str,
}

#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusPage {
    pub title: &'static str,
    pub pages: &'static [Page],
    pub user: Option<User>,
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
