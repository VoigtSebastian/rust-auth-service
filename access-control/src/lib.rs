use std::future::Future;
use std::pin::Pin;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid credentials")]
    Authentication,
    #[error("Permission denied")]
    Authorization,
}

pub trait Backend<U>: Clone {
    fn get_user(&self, email: &str, password: &str) -> Pin<Box<dyn Future<Output = Option<U>>>>;
}

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub permissions: String,
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
    pub async fn authenticate(
        self,
        email: &str,
        password: &str,
    ) -> Result<AccessControl<B, Authenticated>, Error> {
        let user = self
            .backend
            .get_user(email, password)
            .await
            .ok_or(Error::Authentication)?;
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
