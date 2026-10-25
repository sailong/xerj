//! Executable statement of the second-brain authorization posture (issue #79).
//!
//! A brain **is** a security boundary. This file is the inverted descendant of
//! `brain_is_not_a_security_boundary.rs`, which pinned the measured fact that
//! one did *not* exist: any authenticated caller could read, write, forge and
//! destroy every brain, and `GET /_mapping` handed over the list of brain
//! names so the attacker did not even have to guess one. Every assertion that
//! file made now runs in reverse.
//!
//! The point of enumerating so many doors is that the exposure was never about
//! the four `/_graph/*` handlers. A brain's edges live in an ordinary index and
//! `IndexName::validate` admits a leading `.`, so `.xerj-memory-{brain}-edges`
//! was reachable through the generic ES-compat surface *and* through the
//! native router's `/v1/indices/{name}/…` spelling. An access check on
//! `/_graph/*` alone would have left all of that open — a boundary that only
//! looks like one. So this test walks every door, and a fix that closes only
//! some of them fails here.
//!
//! Every request below is made with a **minted, non-admin** API key, because
//! the issue is about what an ordinary authenticated caller can reach — not
//! about the superuser.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;
use xerj_api::{
    router::{build_es_compat_router, build_native_router},
    state::AppState,
};
use xerj_common::{config::Config, metrics::Metrics};
use xerj_engine::Engine;

const ADMIN_KEY: &str = "admin-secret-key-for-boundary-test";

/// Fixture instants. Pinned rather than "now" so a link and the `as_of` that
/// reads it back can never land in the same millisecond.
const T0: i64 = 1_753_600_000_000;
const AS_OF: i64 = 1_753_700_000_000;

/// An auth-enabled node over a fresh data directory. The `TempDir` is returned
/// and must be held for the whole test: the Engine keeps the directory open,
/// and these are engine data dirs, so leaking them fills `/tmp`.
fn auth_enabled_state() -> (AppState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_over(dir.path().to_str().unwrap(), true);
    (state, dir)
}

fn state_over(data_dir: &str, auth: bool) -> AppState {
    let mut config = Config::default();
    config.server.data_dir = data_dir.to_string();
    config.auth.enabled = auth;
    config.auth.admin_api_key = if auth {
        ADMIN_KEY.to_string()
    } else {
        String::new()
    };
    let metrics = Metrics::new().expect("metrics");
    let engine = Engine::new(config.clone()).expect("engine");
    AppState::new(config, engine, metrics)
}

/// Like [`send`] but returns the body verbatim — `_cat` answers a plain-text
/// table, which is exactly the shape the line-level pruning has to handle.
async fn send_text(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if !auth.is_empty() {
        builder = builder.header("authorization", auth);
    }
    let req = builder.body(Body::empty()).expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &str,
    body: &str,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if !auth.is_empty() {
        builder = builder.header("authorization", auth);
    }
    let req = builder.body(Body::from(body.to_string())).expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Mint an API key with the given JSON body and return its `Authorization`
/// header value.
async fn mint(app: &axum::Router, minter: &str, body: &str) -> String {
    let (status, resp) = send(app, "POST", "/_security/api_key", minter, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "minting a key should succeed: {resp}"
    );
    let encoded = resp["encoded"].as_str().expect("encoded key").to_string();
    format!("ApiKey {encoded}")
}

/// A key scoped to exactly one brain: its edges index and its nodes index.
/// This is the documented grant shape from `graph_api`'s module docs.
fn brain_grant(brain: &str, privileges: &str) -> String {
    format!(
        r#"{{"name":"{brain}-agent","role_descriptors":{{"{brain}":{{"indices":[
             {{"names":[".xerj-memory-{brain}-edges",".xerj-memory-{brain}"],
               "privileges":[{privileges}]}}]}}}}}}"#
    )
}

/// Seed two brains, as the admin, so there is something to keep apart.
async fn seed_two_brains(app: &axum::Router) {
    let admin = format!("ApiKey {ADMIN_KEY}");
    for (brain, dst) in [("alice", "doc:2"), ("bob", "secret:2")] {
        let (status, body) = send(
            app,
            "POST",
            &format!("/_graph/{brain}/link"),
            &admin,
            &format!(
                r#"{{"src":"doc:1","type":"mentions","dst":"{dst}",
                     "valid_at":{T0},"created_at":{T0}}}"#
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "seeding {brain}: {body}");
    }
    let (status, _) = send(app, "POST", "/.xerj-memory-bob-edges/_refresh", &admin, "").await;
    assert_eq!(status, StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────────────────────

/// Every door into someone else's brain, walked with a credential scoped to a
/// different brain. This is the assertion the issue asked for, and the exact
/// inverse of what the previous test measured.
#[tokio::test]
async fn a_scoped_caller_cannot_reach_another_brain_through_any_door() {
    let (state, _data_dir) = auth_enabled_state();
    let app = build_es_compat_router(state.clone());
    let native = build_native_router(state);
    seed_two_brains(&app).await;

    let admin = format!("ApiKey {ADMIN_KEY}");
    let alice = mint(&app, &admin, &brain_grant("alice", r#""read","write""#)).await;

    // ── 1. The graph API: all four entry points, denied for bob. ───────────
    for (method, uri) in [
        ("GET", "/_graph/bob/ego?node=doc:1"),
        ("GET", "/_graph/bob/overview"),
        ("POST", "/_graph/bob/link"),
        ("DELETE", "/_graph/bob/link/whatever"),
    ] {
        let (status, body) = send(
            &app,
            method,
            uri,
            &alice,
            r#"{"src":"a","type":"mentions","dst":"b"}"#,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be forbidden, got {status}: {body}"
        );
    }

    // ── 2. The raw index surface, which is where the real exposure lived. ──
    // Read around `/_graph`, forge an edge past the derived-`edge_id`
    // invariant, refresh, and destroy the brain outright.
    for (method, uri, body) in [
        (
            "POST",
            "/.xerj-memory-bob-edges/_search",
            r#"{"query":{"match_all":{}}}"#,
        ),
        (
            "POST",
            "/.xerj-memory-bob-edges/_doc/forged",
            r#"{"edge_id":"forged","src":"doc:1","dst":"attacker:payload","type":"mentions"}"#,
        ),
        ("POST", "/.xerj-memory-bob-edges/_refresh", ""),
        ("GET", "/.xerj-memory-bob-edges/_doc/anything", ""),
        ("DELETE", "/.xerj-memory-bob-edges", ""),
        // Percent-encoded, in case the check compared raw path text.
        ("POST", "/%2Exerj-memory-bob-edges/_search", "{}"),
    ] {
        let (status, resp) = send(&app, method, uri, &alice, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be forbidden, got {status}: {resp}"
        );
    }

    // ── 2b. Patterns are answered, not refused — over the caller's visible
    // set only. Refusing them outright was the first cut of this fix and it
    // cost every legitimate `logs-*` grant; expanding them over what the
    // principal may see is both usable and closed. What must never appear is
    // one byte of bob's.
    for uri in [
        "/.xerj-memory-*/_search",
        "/*/_search",
        "/_all/_search",
        "/.xerj-memory-bob*/_search",
    ] {
        let (status, resp) = send(&app, "POST", uri, &alice, "{}").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "POST {uri} should be answered over the visible set, got {status}: {resp}"
        );
        assert!(
            !resp.to_string().contains("bob"),
            "POST {uri} leaked bob: {resp}"
        );
    }

    // ── 3. The agent-memory surface: bob's brain keeps its NODES in the
    // `.xerj-memory-bob` namespace, so `/_memory/*` is a door to the same data.
    for (method, uri) in [
        ("POST", "/_memory/bob/_recall"),
        ("GET", "/_memory/bob"),
        ("POST", "/_memory/bob"),
        ("DELETE", "/_memory/bob"),
        ("DELETE", "/_memory/bob/some-id"),
    ] {
        let (status, resp) = send(&app, method, uri, &alice, r#"{"text":"x","query":"x"}"#).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{method} {uri} must be forbidden, got {status}: {resp}"
        );
    }

    // ── 4. Enumeration: a scoped caller gets metadata for the indices it
    // holds and no trace of anything else, so brain names stay unguessable
    // WITHOUT the blanket 403 that stopped Kibana from working at all.
    for uri in [
        "/_mapping",
        "/_cat/indices",
        "/_alias",
        "/_settings",
        "/_cluster/stats",
        "/_resolve/index/*",
        "/_cluster/health",
        "/_nodes",
    ] {
        let (status, resp) = send(&app, "GET", uri, &alice, "").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET {uri} must be answered for a scoped key, got {status}: {resp}"
        );
        assert!(
            !resp.to_string().contains("bob"),
            "GET {uri} enumerated bob's brain: {resp}"
        );
    }
    let (status, table) = send_text(&app, "GET", "/_cat/indices", &alice).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !table.contains("bob"),
        "_cat/indices enumerated bob's brain: {table}"
    );

    // ── 5. Unnamed fan-out. `POST /_search` with no index reads every index
    // the caller can see — which is alice's, and only alice's. The global
    // verbs are the default paths of every ES client, so they answer; what
    // they must not do is answer with someone else's data.
    for (method, uri, body) in [
        ("POST", "/_search", "{}"),
        ("POST", "/_msearch", "{}\n{\"query\":{\"match_all\":{}}}\n"),
        ("POST", "/_count", "{}"),
    ] {
        let (status, resp) = send(&app, method, uri, &alice, body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{method} {uri} must be answered over the visible set, got {status}: {resp}"
        );
        assert!(
            !resp.to_string().contains("bob"),
            "{method} {uri} leaked bob: {resp}"
        );
    }
    // The global write path works for the caller's own index …
    let (status, resp) = send(
        &app,
        "POST",
        "/_bulk",
        &alice,
        "{\"index\":{\"_index\":\".xerj-memory-alice-edges\",\"_id\":\"own\"}}\n{\"src\":\"a\"}\n",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "global _bulk into its own index must work: {resp}"
    );
    // … and refuses the moment the body names someone else's.
    for body in [
        "{\"index\":{\"_index\":\".xerj-memory-bob-edges\",\"_id\":\"forged\"}}\n{\"src\":\"a\"}\n",
        "{\"delete\":{\"_index\":\".xerj-memory-bob-edges\",\"_id\":\"e1\"}}\n",
    ] {
        let (status, resp) = send(&app, "POST", "/_bulk", &alice, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a body-named _bulk into bob must be forbidden, got {status}: {resp}"
        );
    }
    // Same for the body-named forms of _msearch and _mget.
    let (status, resp) = send(
        &app,
        "POST",
        "/_msearch",
        &alice,
        "{\"index\":\".xerj-memory-bob-edges\"}\n{\"query\":{\"match_all\":{}}}\n",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body-named _msearch: {resp}");
    let (status, resp) = send(
        &app,
        "POST",
        "/_mget",
        &alice,
        "{\"docs\":[{\"_index\":\".xerj-memory-bob-edges\",\"_id\":\"x\"}]}",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body-named _mget: {resp}");

    // ── 6. The native router is the same engine under a different spelling.
    for (method, uri) in [
        ("POST", "/v1/indices/.xerj-memory-bob-edges/search"),
        ("GET", "/v1/indices/.xerj-memory-bob-edges"),
        ("DELETE", "/v1/indices/.xerj-memory-bob-edges"),
        ("POST", "/v1/indices/.xerj-memory-bob-edges/docs"),
    ] {
        let (status, resp) = send(&native, method, uri, &alice, r#"{"query":{}}"#).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "native {method} {uri} must be forbidden, got {status}: {resp}"
        );
    }

    // ── 7. Escalation: a scoped caller must not be able to mint itself a key
    // that grants bob.
    let (status, resp) = send(
        &app,
        "POST",
        "/_security/api_key",
        &alice,
        &brain_grant("bob", r#""all""#),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a scoped key must not mint keys, got {status}: {resp}"
    );

    // ── 8. Existence must not leak through the status code: a brain that does
    // not exist is refused exactly like one that does.
    let (status, _) = send(&app, "GET", "/_graph/nosuchbrain/overview", &alice, "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "403 (not 404) for an unauthorized brain, or the code maps the node"
    );
}

/// The boundary is only worth anything if the authorized side still works.
/// A key scoped to `alice` must be able to do everything a brain owner does.
#[tokio::test]
async fn a_scoped_caller_retains_full_use_of_its_own_brain() {
    let (state, _data_dir) = auth_enabled_state();
    let app = build_es_compat_router(state);
    seed_two_brains(&app).await;

    let admin = format!("ApiKey {ADMIN_KEY}");
    let alice = mint(&app, &admin, &brain_grant("alice", r#""read","write""#)).await;

    // Write.
    let (status, body) = send(
        &app,
        "POST",
        "/_graph/alice/link",
        &alice,
        &format!(
            r#"{{"src":"doc:1","type":"mentions","dst":"doc:3",
                 "valid_at":{T0},"created_at":{T0}}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "own-brain link failed: {body}");
    let edge_id = body["edge_id"].as_str().expect("edge_id").to_string();

    let (status, _) = send(
        &app,
        "POST",
        "/.xerj-memory-alice-edges/_refresh",
        &alice,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own backing index is usable");

    // Read, both entry points.
    let (status, ego) = send(
        &app,
        "GET",
        &format!("/_graph/alice/ego?node=doc:1&as_of={AS_OF}"),
        &alice,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own-brain ego failed: {ego}");
    assert!(
        ego.to_string().contains("doc:3"),
        "own edge should be visible: {ego}"
    );
    let (status, overview) = send(
        &app,
        "GET",
        &format!("/_graph/alice/overview?as_of={AS_OF}"),
        &alice,
        "",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "own-brain overview failed: {overview}"
    );

    // Invalidate.
    let (status, body) = send(
        &app,
        "DELETE",
        &format!("/_graph/alice/link/{edge_id}"),
        &alice,
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "own-brain unlink failed: {body}");

    // A read-only grant reads but does not write — the privilege half of the
    // model, not just the resource half.
    let reader = mint(&app, &admin, &brain_grant("alice", r#""read""#)).await;
    let (status, _) = send(&app, "GET", "/_graph/alice/overview", &reader, "").await;
    assert_eq!(status, StatusCode::OK, "read grant must read");
    let (status, _) = send(
        &app,
        "POST",
        "/_graph/alice/link",
        &reader,
        r#"{"src":"a","type":"mentions","dst":"b"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "read grant must not write");
    let (status, _) = send(&app, "DELETE", "/.xerj-memory-alice-edges", &reader, "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "read grant must not destroy the brain"
    );

    // Resource granularity within one brain: the notes and the link graph are
    // two indices, and `POST /_memory/{ns}/_recall` with `graph:` reads the
    // second. A credential given only the notes must not get the graph through
    // the side door — while plain recall over the notes it *was* granted keeps
    // working.
    let notes_only = mint(
        &app,
        &admin,
        r#"{"name":"notes-only","role_descriptors":{"n":{"indices":[
             {"names":[".xerj-memory-alice"],"privileges":["read"]}]}}}"#,
    )
    .await;
    let (status, _) = send(
        &app,
        "POST",
        "/_memory/alice/_recall",
        &notes_only,
        r#"{"query":"anything"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "plain recall on the granted notes");
    let (status, resp) = send(
        &app,
        "POST",
        "/_memory/alice/_recall",
        &notes_only,
        r#"{"query":"anything","graph":{"mode":"restrict","seeds":["doc:1"]}}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "graph coupling reads the edges index and needs its own grant: {resp}"
    );
}

/// The fail-closed half. A key minted with no `role_descriptors` — the shape
/// every key had before this existed — holds **nothing** in the reserved
/// namespace, and cannot mint itself out of that.
#[tokio::test]
async fn an_unconfigured_key_is_denied_every_brain_and_cannot_escalate() {
    let (state, _data_dir) = auth_enabled_state();
    let app = build_es_compat_router(state);
    seed_two_brains(&app).await;

    let admin = format!("ApiKey {ADMIN_KEY}");
    let legacy = mint(&app, &admin, r#"{"name":"legacy"}"#).await;

    for (method, uri) in [
        ("GET", "/_graph/alice/ego?node=doc:1"),
        ("GET", "/_graph/bob/overview"),
        ("POST", "/_graph/alice/link"),
        ("POST", "/.xerj-memory-alice-edges/_search"),
        ("DELETE", "/.xerj-memory-bob-edges"),
        ("POST", "/_memory/alice/_recall"),
    ] {
        let (status, resp) = send(
            &app,
            method,
            uri,
            &legacy,
            r#"{"src":"a","type":"t","dst":"b","query":"x"}"#,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "unconfigured key on {method} {uri} must be denied, got {status}: {resp}"
        );
    }

    // It keeps its historical reach over ordinary indices — broad RBAC over the
    // general surface is still deferred, and this fix does not pretend
    // otherwise.
    let (status, resp) = send(&app, "PUT", "/logs-2026", &legacy, "{}").await;
    assert!(
        status.is_success(),
        "a legacy key must still create an ordinary index, got {status}: {resp}"
    );
    let (status, resp) = send(
        &app,
        "POST",
        "/logs-2026/_doc/1",
        &legacy,
        r#"{"msg":"hello"}"#,
    )
    .await;
    assert!(
        status.is_success(),
        "a legacy key must still write an ordinary index, got {status}: {resp}"
    );

    // But enumeration hides the brains: `_mapping` answers, without them.
    let (status, mapping) = send(&app, "GET", "/_mapping", &legacy, "").await;
    assert_eq!(status, StatusCode::OK, "metadata still answers");
    let text = mapping.to_string();
    assert!(
        !text.contains(".xerj-memory-"),
        "brain names must not be enumerable: {text}"
    );
    assert!(
        text.contains("logs-2026"),
        "ordinary indices are still listed: {text}"
    );
    let (status, cat) = send_text(&app, "GET", "/_cat/indices", &legacy).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !cat.contains(".xerj-memory-"),
        "_cat/indices must not enumerate brains: {cat}"
    );
    assert!(
        cat.contains("logs-2026"),
        "_cat/indices still lists ordinary indices: {cat}"
    );

    // And it cannot mint its way in: `role_descriptors` from a non-superuser
    // are dropped, so the child key is unscoped too.
    let child = mint(&app, &legacy, &brain_grant("bob", r#""all""#)).await;
    let (status, resp) = send(&app, "GET", "/_graph/bob/overview", &child, "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key minted by a non-superuser must not carry grants: {resp}"
    );
}

/// The local-dev path must not have moved. `xerj --insecure` /
/// point-at-a-folder has one user and no configuration; every brain stays
/// reachable with no credential at all.
#[tokio::test]
async fn insecure_single_user_mode_is_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state = state_over(dir.path().to_str().unwrap(), false);
    let app = build_es_compat_router(state);

    for brain in ["alice", "bob"] {
        let (status, body) = send(
            &app,
            "POST",
            &format!("/_graph/{brain}/link"),
            "",
            r#"{"src":"doc:1","type":"mentions","dst":"doc:2"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "insecure link failed: {body}");
        let (status, _) = send(&app, "GET", &format!("/_graph/{brain}/overview"), "", "").await;
        assert_eq!(status, StatusCode::OK, "insecure overview must work");
    }
    // Including the doors a scoped key is refused: there is nothing to scope.
    let (status, _) = send(&app, "GET", "/_mapping", "", "").await;
    assert_eq!(status, StatusCode::OK, "insecure enumeration must work");
    let (status, cat) = send_text(&app, "GET", "/_cat/indices", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        cat.contains(".xerj-memory-"),
        "the single local user still sees their own brains: {cat}"
    );
    let (status, _) = send(
        &app,
        "POST",
        "/_search",
        "",
        r#"{"query":{"match_all":{}}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "insecure fan-out must work");
}

/// Grants are persisted with the key. A node restart must not silently turn a
/// scoped key back into an unscoped one — nor, worse, into a superuser.
#[tokio::test]
async fn grants_survive_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().to_str().unwrap().to_string();

    // Scope the first node so its data-dir lock is released before the second
    // one boots over the same directory.
    let alice = {
        let state = state_over(&data_dir, true);
        let app = build_es_compat_router(state.clone());
        seed_two_brains(&app).await;
        let admin = format!("ApiKey {ADMIN_KEY}");
        let alice = mint(&app, &admin, &brain_grant("alice", r#""read","write""#)).await;
        drop(app);
        drop(state);
        alice
    };

    // Boot a second engine over the same data directory — the restart.
    let restarted = build_es_compat_router(state_over(&data_dir, true));

    let (status, resp) = send(&restarted, "GET", "/_graph/alice/overview", &alice, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the grant must survive restart, got {status}: {resp}"
    );
    let (status, resp) = send(&restarted, "GET", "/_graph/bob/overview", &alice, "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the boundary must survive restart, got {status}: {resp}"
    );
}

async fn wildcard_auth_fixture() -> (axum::Router, tempfile::TempDir, String, String, String) {
    let (state, dir) = auth_enabled_state();
    let app = build_es_compat_router(state);
    let admin = format!("ApiKey {ADMIN_KEY}");
    for index in ["audit-a", "other-a"] {
        let (status, body) = send(
            &app,
            "PUT",
            &format!("/{index}/_doc/1?refresh=true"),
            &admin,
            r#"{"message":"original"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let reader = mint(&app, &admin, r#"{"name":"reader","role_descriptors":{"r":{"indices":[{"names":["audit-a"],"privileges":["read"]}]}}}"#).await;
    let writer = mint(&app, &admin, r#"{"name":"writer","role_descriptors":{"r":{"indices":[{"names":["audit-a"],"privileges":["write"]}]}}}"#).await;
    (app, dir, admin, reader, writer)
}

#[tokio::test]
async fn wildcard_authorization_refuses_read_only_mutations_before_any_change() {
    let (app, _dir, admin, reader, _) = wildcard_auth_fixture().await;
    let (_, settings_before) = send(&app, "GET", "/audit-a/_settings", &admin, "").await;
    for (method, uri, body) in [
        (
            "POST",
            "/audit-*/_delete_by_query",
            r#"{"query":{"match_all":{}}}"#,
        ),
        (
            "POST",
            "/audit-*/_update_by_query",
            r#"{"script":{"source":"ctx._source.message = 'changed'"},"query":{"match_all":{}}}"#,
        ),
        (
            "PUT",
            "/audit-*/_settings",
            r#"{"index":{"number_of_replicas":7}}"#,
        ),
        (
            "POST",
            "/_bulk",
            "{\"delete\":{\"_index\":\"audit-*\",\"_id\":\"1\"}}\n",
        ),
    ] {
        let (status, response) = send(&app, method, uri, &reader, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {response}");
        let (status, doc) = send(&app, "GET", "/audit-a/_doc/1", &admin, "").await;
        assert_eq!(status, StatusCode::OK, "{doc}");
        assert_eq!(doc["_source"]["message"], "original");
        let (_, settings_after) = send(&app, "GET", "/audit-a/_settings", &admin, "").await;
        assert_eq!(settings_before, settings_after);
    }
}

#[tokio::test]
async fn wildcard_authorization_refuses_write_only_reads_including_global_queries() {
    let (app, _dir, _, _, writer) = wildcard_auth_fixture().await;
    for uri in ["/audit-*/_search", "/_all/_search", "/_search", "/_count"] {
        let (status, body) =
            send(&app, "POST", uri, &writer, r#"{"query":{"match_all":{}}}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
    let (status, body) = send(
        &app,
        "POST",
        "/_msearch",
        &writer,
        "{\"index\":\"audit-*\"}\n{\"query\":{\"match_all\":{}}}\n",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn wildcard_authorization_preserves_scoped_reads_and_mixed_reindex() {
    let (app, _dir, admin, reader, _) = wildcard_auth_fixture().await;
    for uri in ["/audit-*/_search", "/_all/_search", "/_search"] {
        let (status, body) =
            send(&app, "POST", uri, &reader, r#"{"query":{"match_all":{}}}"#).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        let hits = body["hits"]["hits"].as_array().expect("hits");
        assert_eq!(hits.len(), 1, "{body}");
        assert_eq!(hits[0]["_index"], "audit-a");
    }
    let copier = mint(&app, &admin, r#"{"name":"copier","role_descriptors":{"r":{"indices":[{"names":["audit-a"],"privileges":["read"]},{"names":["copied-a"],"privileges":["write"]}]}}}"#).await;
    let (status, body) = send(&app, "PUT", "/audit-a/_alias/audit-source", &admin, "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &app,
        "POST",
        "/_reindex?refresh=true",
        &copier,
        r#"{"source":{"index":"audit-source"},"dest":{"index":"copied-a"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, doc) = send(&app, "GET", "/copied-a/_doc/1", &admin, "").await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    assert_eq!(doc["_source"]["message"], "original");

    let (status, body) = send(
        &app,
        "POST",
        "/_reindex",
        &copier,
        r#"{"source":{"index":"copied-*"},"dest":{"index":"copied-a"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn wildcard_authorization_msearch_uses_the_executed_header_target() {
    let (app, _dir, _, reader, writer) = wildcard_auth_fixture().await;
    for header in [
        r#"{"index":[]}"#,
        r#"{"index":["other-a"]}"#,
        r#"{"index":[1]}"#,
        r#"{"index":null}"#,
        r#"{"index":""}"#,
        r#"{"index":", "}"#,
        r#"{}"#,
    ] {
        for (op, query) in [
            ("_msearch", r#"{"query":{"match_all":{}}}"#),
            (
                "_msearch/template",
                r#"{"source":{"query":{"match_all":{}}}}"#,
            ),
        ] {
            let payload = format!("{header}\n{query}\n");
            let (status, body) = send(&app, "POST", &format!("/{op}"), &writer, &payload).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{op} {header}: {body}");
            let (status, body) =
                send(&app, "POST", &format!("/audit-a/{op}"), &reader, &payload).await;
            assert_eq!(status, StatusCode::OK, "{op} {header}: {body}");
            let hits = body["responses"][0]["hits"]["hits"]
                .as_array()
                .unwrap_or_else(|| panic!("{op} {header}: {body}"));
            assert_eq!(hits.len(), 1, "{body}");
            assert_eq!(hits[0]["_index"], "audit-a");
        }
    }
}

#[tokio::test]
async fn wildcard_authorization_sql_requires_read_on_the_parsed_table() {
    let (app, _dir, admin, _, _) = wildcard_auth_fixture().await;
    let (status, body) = send(
        &app,
        "PUT",
        "/audit_a/_doc/1?refresh=true",
        &admin,
        r#"{"message":"original"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let reader = mint(&app, &admin, r#"{"name":"sql-reader","role_descriptors":{"r":{"indices":[{"names":["audit_a"],"privileges":["read"]}]}}}"#).await;
    let writer = mint(&app, &admin, r#"{"name":"sql-writer","role_descriptors":{"r":{"indices":[{"names":["audit_a"],"privileges":["write"]}]}}}"#).await;
    let query = r#"{"query":"SELECT * FROM audit_a"}"#;
    let (status, body) = send(&app, "POST", "/_sql", &writer, query).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(&app, "POST", "/_sql", &reader, query).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0][0], "original", "{body}");
}

#[tokio::test]
async fn wildcard_authorization_clone_targets_are_checked_before_creation() {
    let (app, _dir, admin, _, _) = wildcard_auth_fixture().await;
    let manager = mint(&app, &admin, r#"{"name":"manager","role_descriptors":{"r":{"indices":[{"names":["audit-a","copied-*"],"privileges":["manage"]}]}}}"#).await;
    let limited = mint(&app, &admin, r#"{"name":"limited","role_descriptors":{"r":{"indices":[{"names":["audit-a"],"privileges":["manage"]}]}}}"#).await;
    for op in ["_clone", "_shrink", "_split"] {
        let target = format!("copied-{}", &op[1..]);
        let uri = format!("/audit-a/{op}/{target}");
        let (status, body) = send(&app, "POST", &uri, &limited, "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        let (status, body) = send(&app, "HEAD", &format!("/{target}"), &admin, "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = send(&app, "POST", &uri, &manager, "{}").await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        let (status, body) = send(&app, "GET", &format!("/{target}/_doc/1"), &admin, "").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["_source"]["message"], "original");
    }
}

#[tokio::test]
async fn wildcard_authorization_rollover_refusal_preserves_generation() {
    let (state, dir) = auth_enabled_state();
    state
        .engine
        .create_data_stream("audit-roll")
        .expect("stream");
    let app = build_es_compat_router(state.clone());
    let admin = format!("ApiKey {ADMIN_KEY}");
    let limited = mint(&app, &admin, r#"{"name":"limited","role_descriptors":{"r":{"indices":[{"names":[".ds-audit-roll-000001"],"privileges":["manage"]}]}}}"#).await;
    let before = state.engine.data_streams.get("audit-roll").unwrap().clone();
    let aliases_before = state.engine.aliases.get("audit-roll").unwrap().clone();
    let persisted_before = std::fs::read(dir.path().join("cluster_state.json")).unwrap();
    let (status, body) = send(&app, "POST", "/audit-roll/_rollover", &limited, "{}").await;
    assert!(!status.is_success(), "{body}");
    let after = state.engine.data_streams.get("audit-roll").unwrap().clone();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.backing_indices, before.backing_indices);
    assert_eq!(
        *state.engine.aliases.get("audit-roll").unwrap(),
        aliases_before
    );
    assert_eq!(
        std::fs::read(dir.path().join("cluster_state.json")).unwrap(),
        persisted_before
    );
    assert!(!state
        .engine
        .index_name_list()
        .contains(&".ds-audit-roll-000002".to_string()));
    let manager = mint(&app, &admin, r#"{"name":"manager","role_descriptors":{"r":{"indices":[{"names":[".ds-audit-roll-*"],"privileges":["manage"]}]}}}"#).await;
    let (status, body) = send(&app, "POST", "/audit-roll/_rollover", &manager, "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["new_index"], ".ds-audit-roll-000002");
}

#[tokio::test]
async fn wildcard_authorization_date_math_matches_the_concrete_grant() {
    let (state, _dir) = auth_enabled_state();
    let app = build_es_compat_router(state);
    let admin = format!("ApiKey {ADMIN_KEY}");
    let expression = "<audit-{now/d}>";
    let concrete = xerj_api::es_compat::resolve_date_math_index(expression);
    let grant = serde_json::json!({"name":"date","role_descriptors":{"r":{"indices":[
        {"names":[concrete],"privileges":["read","write","manage"]}
    ]}}});
    let key = mint(&app, &admin, &grant.to_string()).await;
    let path = "/%3Caudit-%7Bnow%2Fd%7D%3E";
    let (status, body) = send(&app, "PUT", path, &key, "{}").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &app,
        "PUT",
        &format!("/{concrete}/_doc/date"),
        &key,
        r#"{"message":"dated"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = send(
        &app,
        "POST",
        &format!("{path}/_search"),
        &key,
        r#"{"query":{"match_all":{}}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["hits"]["hits"][0]["_source"]["message"], "dated");
}

#[tokio::test]
async fn wildcard_authorization_rollover_second_check_preserves_generation() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct RefuseSecond(AtomicUsize);
    impl xerj_engine::index_guard::IndexVisibility for RefuseSecond {
        fn visible(&self, _: &str) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst) == 0
        }
    }
    let (state, dir) = auth_enabled_state();
    state.engine.create_data_stream("audit-roll").unwrap();
    let before = std::fs::read(dir.path().join("cluster_state.json")).unwrap();
    let guard = Arc::new(RefuseSecond(AtomicUsize::new(0)));
    let result = xerj_engine::index_guard::scoped(guard.clone(), async {
        state.engine.rollover_data_stream("audit-roll")
    })
    .await;
    assert!(result.is_err());
    assert_eq!(guard.0.load(Ordering::SeqCst), 2);
    let stream = state.engine.data_streams.get("audit-roll").unwrap();
    assert_eq!(stream.generation, 1);
    assert_eq!(stream.backing_indices, [".ds-audit-roll-000001"]);
    assert_eq!(
        std::fs::read(dir.path().join("cluster_state.json")).unwrap(),
        before
    );
    assert!(!dir.path().join(".ds-audit-roll-000002").exists());
}

async fn by_query_requires_write_after_alias_resolution(op: &str) {
    use std::{collections::HashSet, sync::Arc};
    use xerj_api::auth::Principal;
    use xerj_engine::rbac::{Privilege, Role};

    let (state, _dir) = auth_enabled_state();
    let setup = build_es_compat_router(state.clone());
    let admin = format!("ApiKey {ADMIN_KEY}");
    let (status, body) = send(
        &setup,
        "PUT",
        "/readonly/_doc/1?refresh=true",
        &admin,
        r#"{"message":"original"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let key = mint(&setup, &admin, r#"{"name":"mixed","role_descriptors":{"r":{"indices":[{"names":["readonly"],"privileges":["read"]},{"names":["writable"],"privileges":["write"]}]}}}"#).await;
    state.engine.add_alias("work", "readonly").unwrap();
    let principal = Principal::Scoped {
        key_id: "mixed".into(),
        roles: vec![
            Role::new(
                "reader",
                HashSet::from([Privilege::ReadIndex]),
                vec!["readonly".into()],
            ),
            Role::new(
                "writer",
                HashSet::from([Privilege::WriteIndex]),
                vec!["writable".into()],
            ),
        ],
    };
    // Model a completed preflight followed by alias retargeting: handlers must
    // check the concrete mutation target even under an any-privilege guard.
    let app = axum::Router::new()
        .route(
            "/:index/_delete_by_query",
            axum::routing::post(xerj_api::es_compat::delete_by_query),
        )
        .route(
            "/:index/_update_by_query",
            axum::routing::post(xerj_api::es_compat::update_by_query),
        )
        .with_state(state);
    let payload =
        r#"{"query":{"match_all":{}},"script":{"source":"ctx._source.message = 'changed'"}}"#;
    let guard: Arc<dyn xerj_engine::index_guard::IndexVisibility> =
        xerj_api::authz::visibility_for(&principal);
    let (status, body) = xerj_engine::index_guard::scoped(
        guard,
        send(&app, "POST", &format!("/work/{op}"), &key, payload),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send(&setup, "GET", "/readonly/_doc/1", &admin, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["_source"]["message"], "original");
}

#[tokio::test]
async fn wildcard_authorization_delete_by_query_rechecks_the_concrete_action() {
    by_query_requires_write_after_alias_resolution("_delete_by_query").await;
}

#[tokio::test]
async fn wildcard_authorization_update_by_query_rechecks_the_concrete_action() {
    by_query_requires_write_after_alias_resolution("_update_by_query").await;
}
