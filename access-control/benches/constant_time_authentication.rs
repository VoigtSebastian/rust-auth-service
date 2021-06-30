//! Test that the authentication functionality is roughtly in constant time to prevent user enumeration
use access_control::{AccessControl, Backend, FutureOption, FutureResult, User};

use criterion::async_executor::FuturesExecutor;
use criterion::black_box;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use futures_util::future::ready;

#[derive(Debug, Clone)]
struct TestUser;

impl User for TestUser {
    fn username(&self) -> &str {
        unimplemented!()
    }

    fn password_hash(&self) -> &str {
        // password: password and salt: saltsaltsaltsalt
        "$argon2id$v=19$m=15360,t=2,p=1$saltsaltsaltsalt$KeAk3tjH2+Oco39/F4GKCJL3dXFv/fRN/IBr9XT6PEA"
    }

    fn capabilities(&self) -> &std::collections::HashSet<String> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
struct TestBackend;

impl Backend for TestBackend {
    type User = TestUser;

    fn get_user(&self, _username: impl AsRef<str>) -> FutureOption<TestUser> {
        Box::pin(ready(Some(TestUser)))
    }

    fn get_user_from_session(&self, _session_id: impl AsRef<str>) -> FutureOption<TestUser> {
        unimplemented!()
    }

    fn register_user(
        &self,
        _username: impl AsRef<str>,
        _password_hash: impl AsRef<str>,
    ) -> FutureResult<()> {
        unimplemented!()
    }

    fn store_session(&self, _user: &TestUser, _session_id: impl AsRef<str>) -> FutureResult<()> {
        unimplemented!()
    }

    fn remove_session(&self, _session_id: impl AsRef<str>) -> FutureResult<()> {
        unimplemented!()
    }
}

async fn test_authenticate_valid(backend: TestBackend, password: &'static str) {
    assert!(AccessControl::new(backend)
        .authenticate_creds("testuser", password)
        .await
        .is_ok())
}

async fn test_authenticate_invalid(backend: TestBackend, password: &'static str) {
    assert!(AccessControl::new(backend)
        .authenticate_creds("testuser", password)
        .await
        .is_err())
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("valid password", |b| {
        b.to_async(FuturesExecutor)
            .iter(|| test_authenticate_valid(TestBackend, black_box("password")));
    });

    c.bench_function("invalid password", |b| {
        b.to_async(FuturesExecutor)
            .iter(|| test_authenticate_invalid(TestBackend, black_box("wrongpassword")));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
