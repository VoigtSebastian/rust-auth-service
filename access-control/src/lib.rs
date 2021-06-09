use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid credentials")]
    Authentication,
    #[error("Permission denied")]
    Authorization,
}

pub trait Backend<U>: Clone
where
    U: User,
{
    fn get_user(&self, email: &str, password: &str) -> Pin<Box<dyn Future<Output = Option<U>>>>;
}

pub trait User {
    fn name(&self) -> &str;
    fn capabilities(&self) -> &HashSet<String>;
}

#[derive(Debug, Clone)]
pub struct AccessControl<S, B, U>
where
    S: AccessControlState,
    B: Backend<U>,
    U: User,
{
    state: S,
    backend: B,
    user: Option<U>,
}

impl<B, U> AccessControl<Start, B, U>
where
    B: Backend<U>,
    U: User,
{
    pub fn new(backend: B) -> Self {
        Self {
            state: Start,
            backend,
            user: None,
        }
    }
}

impl<B, U> AccessControl<Start, B, U>
where
    B: Backend<U>,
    U: User,
{
    pub async fn authenticate(
        self,
        email: &str,
        password: &str,
    ) -> Result<AccessControl<Authenticated, B, U>, Error> {
        let user = self
            .backend
            .get_user(email, password)
            .await
            .ok_or(Error::Authentication)?;
        Ok(AccessControl {
            state: Authenticated,
            backend: self.backend,
            user: Some(user),
        })
    }
}

impl<B, U> AccessControl<Authenticated, B, U>
where
    B: Backend<U>,
    U: User,
{
    pub fn authorize(
        self,
        required_capabilities: &HashSet<String>,
    ) -> Result<AccessControl<Authorized, B, U>, Error> {
        if !self
            .user
            .as_ref()
            .expect("user is always available in authenticated state")
            .capabilities()
            .is_superset(required_capabilities)
        {
            return Err(Error::Authorization);
        }

        Ok(AccessControl {
            state: Authorized,
            backend: self.backend,
            user: self.user,
        })
    }
}

impl<B, U> AccessControl<Authorized, B, U>
where
    B: Backend<U>,
    U: User,
{
    pub fn get_user(self) -> U {
        self.user
            .expect("user is always available in authorized state")
    }
}

// TODO: Seal https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait AccessControlState {}
pub struct Start;
pub struct Authenticated;
pub struct Authorized;

impl AccessControlState for Start {}
impl AccessControlState for Authenticated {}
impl AccessControlState for Authorized {}
