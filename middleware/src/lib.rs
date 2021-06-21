use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use access_control::AccessControl;
use access_control::Backend;
use access_control::User as UserTrait;

use actix_service::{Service, Transform};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::{Payload, PayloadStream, ServiceRequest, ServiceResponse};
use actix_web::error::{
    ErrorBadRequest, ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized,
};
use actix_web::http::header;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse};
use futures_core::Future;
use futures_util::future::{ok, Ready};
use rand::RngCore;
use time::{Duration, OffsetDateTime};

/// A simple type to describe a dynamic Future to make clippy happy.
type DynamicFutureReturn<R> = Pin<Box<dyn Future<Output = R>>>;

pub struct SimpleStringMiddleware<T, U>
where
    T: Backend<U>,
    U: UserTrait,
{
    pub backend: T,
    pub required_capabilities: HashSet<String>,
    phantom: PhantomData<U>,
}

impl<T, U> SimpleStringMiddleware<T, U>
where
    T: Backend<U>,
    U: UserTrait,
{
    pub fn new(backend: T, required_capabilities: HashSet<String>) -> Self {
        Self {
            backend,
            required_capabilities,
            phantom: PhantomData,
        }
    }
}

impl<S, B, T, U> Transform<S> for SimpleStringMiddleware<T, U>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend<U> + 'static + fmt::Debug,
    U: UserTrait + Clone + 'static + fmt::Debug,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthorizationMiddleware<S, T, U>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthorizationMiddleware {
            backend: self.backend.clone(),
            required_capabilities: self.required_capabilities.clone(),
            service: Rc::new(RefCell::new(service)),
            phantom: self.phantom,
        })
    }
}

/// Actix Web middleware to facilitate access control for Actix services.
pub struct AuthorizationMiddleware<S, T, U>
where
    T: Backend<U>,
    U: UserTrait,
{
    backend: T,
    required_capabilities: HashSet<String>,
    /// TODO: Check whether the `Rc<RefCell<S>>` structure is properly implemented and safe.
    /// Especially race conditions have not been checked yet.
    service: Rc<RefCell<S>>,
    phantom: PhantomData<U>,
}

impl<S, B, T, U> Service for AuthorizationMiddleware<S, T, U>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    T: Backend<U> + 'static,
    U: UserTrait + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = DynamicFutureReturn<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut srv = self.service.clone();
        let required_caps = self.required_capabilities.clone();
        let backend = self.backend.clone();

        Box::pin(async move {
            let item = SessionStateItem {
                actions: Vec::new(),
                backend: backend.clone(),
                required_caps,
                phantom: PhantomData,
            };
            req.extensions_mut().insert(item);

            let fut = srv.call(req);
            let mut res = fut.await?;

            let item = res
                .request()
                .extensions_mut()
                .remove::<SessionStateItem<T, U>>()
                .unwrap();

            for action in item.actions {
                match action {
                    SessionStateAction::Login(session_id) => {
                        // Add cookie
                        let cookie = Cookie::build("id", session_id)
                            .secure(true)
                            .http_only(true)
                            .same_site(SameSite::Lax)
                            .path("/")
                            .finish();
                        res.response_mut().add_cookie(&cookie).unwrap();
                    }
                    SessionStateAction::Logout => {
                        if let Some(mut cookie) = res.request().cookie("id") {
                            // Remove database session
                            let _ = backend.remove_session(cookie.value()).await;
                            // Delete the cookie
                            cookie.set_value("");
                            cookie.set_max_age(Duration::zero());
                            cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));
                            res.response_mut().add_cookie(&cookie).unwrap();
                        }
                    }
                }
            }

            Ok(res)
        })
    }
}

#[derive(Debug, Clone)]
enum SessionStateAction {
    Login(String),
    Logout,
}

#[derive(Debug)]
struct SessionStateItem<B, U>
where
    B: Backend<U>,
    U: UserTrait,
{
    actions: Vec<SessionStateAction>,
    backend: B,
    required_caps: HashSet<String>,
    phantom: PhantomData<U>,
}

#[derive(Debug, Clone)]
pub struct SessionState<B, U>
where
    B: Backend<U>,
    U: UserTrait,
{
    req: HttpRequest,
    phantom_backend: PhantomData<B>,
    phantom_user: PhantomData<U>,
}

impl<B, U> SessionState<B, U>
where
    B: Backend<U> + 'static,
    U: UserTrait + 'static,
{
    pub async fn login(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<U, Error> {
        let mut extensions = self.req.extensions_mut();
        let item = extensions
            .get_mut::<SessionStateItem<B, U>>()
            .ok_or_else(|| ErrorInternalServerError("extractor failed"))?;

        // https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#user-ids
        let username = username.as_ref().to_lowercase();

        let user = AccessControl::new(item.backend.clone())
            .authenticate_creds(username, password)
            .await
            .map_err(|_| ErrorUnauthorized("invalid username or password"))?
            .authorize(&HashSet::new())
            .expect("no capabilities required to login")
            .get_user();

        // Use 256 bit length for the session ID. This is double of the minimum required by OWASP.
        let mut key = [0u8; 32];
        // ThreadRng uses a CSPRNG as per
        // https://rust-random.github.io/rand/rand/rngs/index.html#our-generators
        rand::thread_rng().fill_bytes(&mut key);
        let session_id = base64::encode(key);

        item.backend
            .store_session(&user, &session_id)
            .await
            .map_err(|_| ErrorInternalServerError("backend unavailable"))?;

        item.actions.push(SessionStateAction::Login(session_id));

        Ok(user)
    }

    pub async fn logout(&self) {
        if let Some(item) = self
            .req
            .extensions_mut()
            .get_mut::<SessionStateItem<B, U>>()
        {
            item.actions.push(SessionStateAction::Logout);
        }
    }

    /// TODO: Think about what is required to register a user. Maybe other appliances want to store additional user
    /// details like first or last name ...
    pub async fn register(
        &self,
        username: impl AsRef<str>,
        password_hash: impl AsRef<str>,
    ) -> Result<(), Error> {
        let mut extensions = self.req.extensions_mut();
        let item = extensions
            .get_mut::<SessionStateItem<B, U>>()
            .ok_or_else(|| ErrorInternalServerError("extractor failed"))?;

        AccessControl::new(item.backend.clone())
            .register(username, password_hash)
            .await
            .map_err(ErrorBadRequest)
    }
}

impl<B, U> FromRequest for SessionState<B, U>
where
    B: Backend<U>,
    U: UserTrait,
{
    type Config = ();
    type Error = Error;
    type Future = Ready<Result<SessionState<B, U>, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ok(SessionState {
            req: req.clone(),
            phantom_backend: PhantomData,
            phantom_user: PhantomData,
        })
    }
}

pub struct UserDetails<B, U> {
    pub user: U,
    phantom: PhantomData<B>,
}

impl<B, U> FromRequest for UserDetails<B, U>
where
    B: Backend<U> + 'static + fmt::Debug,
    U: UserTrait + Clone + 'static + fmt::Debug,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload<PayloadStream>) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            let login_redirect = || {
                HttpResponse::Found()
                    .header(header::LOCATION, "/login")
                    .finish()
            };

            // Redirect to /login if "id" cookie is not set or we can't find the extensions.
            let cookie = req.cookie("id").ok_or_else(login_redirect)?;
            let mut extensions = req.extensions_mut();
            let item = extensions
                .get_mut::<SessionStateItem<B, U>>()
                .ok_or_else(login_redirect)?;

            // Authenticate and authorize with the session ID
            let user = AccessControl::new(item.backend.clone())
                .authenticate_session(cookie.value())
                .await
                .map_err(|_| ErrorUnauthorized("Invalid credentials"))?
                .authorize(&item.required_caps)
                .map_err(|_| ErrorForbidden("Insufficient permissions"))?
                .get_user();

            Ok(UserDetails {
                user,
                phantom: PhantomData,
            })
        })
    }
}
