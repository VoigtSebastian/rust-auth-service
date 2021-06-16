use std::cell::RefCell;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use access_control::AccessControl;
use access_control::Backend;
use access_control::User;

use actix_service::{Service, Transform};
use actix_session::UserSession;
use actix_web::dev::{Payload, PayloadStream};
use actix_web::error::ErrorInternalServerError;
use actix_web::http::header;
use actix_web::{
    dev::ServiceRequest,
    dev::ServiceResponse,
    error::{ErrorBadRequest, ErrorForbidden},
    Error, HttpResponse,
};
use actix_web::{FromRequest, HttpMessage, HttpRequest};
use futures_core::Future;
use futures_util::future::{ok, Ready};

pub struct SimpleStringMiddleware<T, U>
where
    T: Backend<U>,
    U: User,
{
    pub backend: T,
    pub required_capabilities: HashSet<String>,
    phantom: PhantomData<U>,
}

impl<T, U> SimpleStringMiddleware<T, U>
where
    T: Backend<U>,
    U: User,
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
    T: Backend<U> + 'static,
    U: User + 'static,
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
    U: User,
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
    U: User + 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut srv = self.service.clone();
        let required_caps = self.required_capabilities.clone();
        let backend = self.backend.clone();

        Box::pin(async move {
            // Redirect to /login if "id" cookie is not set.
            let session_id = req.get_session().get::<String>("id")?.ok_or(
                HttpResponse::Found()
                    .header(header::LOCATION, "/login")
                    .finish()
                    .into_body(),
            )?;

            // FIXME: Refactor into function
            let check_access = || -> Pin<Box<dyn Future<Output = Result<(), Error>>>> {
                Box::pin(async {
                    let user = AccessControl::new(backend)
                        .authenticate_session(&session_id)
                        .await
                        .map_err(|_| ErrorBadRequest("Invalid credentials"))?
                        .authorize(&required_caps)
                        .map_err(|_| ErrorForbidden("Permission Denied"))?
                        .get_user();
                    req.extensions_mut().insert(user);
                    Ok(())
                })
            };

            match check_access().await {
                Ok(_) => {
                    let res = srv.call(req).await?;
                    Ok(res)
                }
                Err(e) => Err(e),
            }
        })
    }
}

pub struct UserDetails<U>(pub U);

impl<U> FromRequest for UserDetails<U>
where
    U: User + Clone + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload<PayloadStream>) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            req.extensions()
                .get::<U>()
                .map(|u| UserDetails(u.clone()))
                .ok_or_else(|| ErrorInternalServerError("User not found"))
        })
    }
}
