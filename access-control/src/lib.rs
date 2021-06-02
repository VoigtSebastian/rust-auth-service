#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid credentials")]
    Authentication,
    #[error("Permission denied")]
    Authorization,
}

pub trait Backend<U> {
    fn get_user(&self, credentials: &str) -> Option<U>;
}

#[derive(Debug, Clone)]
pub struct PostgreSqlBackend;
#[derive(Debug, Clone)]
pub struct User {
    name: String,
    permissions: String,
}

impl Backend<User> for PostgreSqlBackend {
    fn get_user(&self, credentials: &str) -> Option<User> {
        Some(User {
            name: "admin".to_string(),
            permissions: credentials.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AccessControl<B, S: AccessControlState>
where
    B: Backend<User>,
{
    backend: B,
    state: S,
}

impl<B> AccessControl<B, Start>
where
    B: Backend<User>,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            state: Start,
        }
    }
}

impl<B> AccessControl<B, Start>
where
    B: Backend<User>,
{
    pub fn authenticate(self, creds: &str) -> Result<AccessControl<B, Authenticated>, Error> {
        let user = self.backend.get_user(creds).ok_or(Error::Authentication)?;
        Ok(AccessControl {
            backend: self.backend,
            state: Authenticated { user },
        })
    }
}

impl<B> AccessControl<B, Authenticated>
where
    B: Backend<User>,
{
    pub fn authorize(self, required_perms: &str) -> Result<AccessControl<B, Authorized>, Error> {
        if self.state.user.permissions != required_perms {
            return Err(Error::Authorization);
        }
        Ok(AccessControl {
            backend: self.backend,
            state: Authorized {
                user: self.state.user,
            },
        })
    }
}

impl<B> AccessControl<B, Authorized>
where
    B: Backend<User>,
{
    pub fn get_user(self) -> User {
        self.state.user
    }
}

// TODO: Seal https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait AccessControlState {}
pub struct Start;
pub struct Authenticated {
    user: User,
}
pub struct Authorized {
    user: User,
}

impl AccessControlState for Start {}
impl AccessControlState for Authenticated {}
impl AccessControlState for Authorized {}
