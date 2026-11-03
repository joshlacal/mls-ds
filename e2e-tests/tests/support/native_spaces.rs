//! Native-archive e2e harness shared by `federation_spaces_full_cutover` and
//! `labyrinth_live_orchestrator`: a loopback ATProto Spaces PDS speaking the
//! exchange catbird-mls's verified native archive performs
//! (`src/client/native_archive_space.rs`), the `clean_slate_federation_fixture`
//! DS process, and the native client's platform transport and key store.
//!
//! PDS semantics follow catbird-sim's `SimPds` and catbird-mls's
//! `NativeArchiveAuthFixture`, over HTTP: an opaque OAuth bearer per account;
//! `getDelegationToken` minted with the account's `#atproto` key; personal
//! mailbox credentials from `getSpaceCredential` (conversation credentials come
//! from the real mls-ds SpaceHost); RFC 9421 credential reads whose audience is
//! the writer, with `Atproto-Space-Want-Mac` answered from the writer's
//! `#atproto_kem` secret; real DAG-CBOR CIDs, LtHash commits, `listRepoOps`
//! replay and STAR `getRepo`. A conversation-Space write commits only after the
//! Space authority accepts the PDS's service-authenticated `notifyWrite`.
//! `notifyCredentialRevoked` / `notifySpaceDeleted` must carry the authority's
//! service auth. DID documents live in one [`DidDirectory`] (the stand-in for
//! PLC / did:web) that every PDS's `resolveDid` serves.
// The PDS handlers' `Err` is the XRPC error response itself.
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};

use anyhow::{Context, Result};
use atproto_spaces::{
    did_resolver::{DidDocument, StaticDidResolver},
    http_signature::verify_credential_request,
    kem::{decapsulate_p256, decode_p256_did_key, encode_p256_did_key},
    lthash::{compute_dagcbor_cid, LtHash},
    mac::{
        compute_commit_mac, compute_record_mac, format_commit_mac_header, format_record_mac_header,
        parse_want_mac_header, COMMIT_MAC_TYPE, RECORD_MAC_TYPE, SPACE_MAC_HEADER_NAME,
        SPACE_WANT_MAC_HEADER_NAME,
    },
    star::{validate_canonical_dagcbor_record, write_star_repo, StarRecordEntry},
    tokens::{
        mint_space_token, verify_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind,
        ATPROTO_KEY_ID, CREDENTIAL_DEFAULT_LIFETIME_SECS, DELEGATION_MAX_LIFETIME_SECS,
    },
    SpaceUri,
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    client::{
        PlatformHttpHeader, PlatformHttpRequest, PlatformHttpResponse, PlatformKeyStore,
        PlatformTransport,
    },
    push::PushKeystore,
    MLSError,
};
use chrono::Utc;
use p256::{
    ecdsa::{signature::Signer as _, Signature, SigningKey, VerifyingKey},
    pkcs8::{EncodePrivateKey as _, LineEnding},
    PublicKey, SecretKey,
};
use rand::RngCore as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio_postgres::{Client as PgClient, NoTls};
use uuid::Uuid;

const MAILBOX: &str = "blue.catbird.labyrinth.mailbox";
const CONVERSATION: &str = "blue.catbird.labyrinth.conversation";

// ---------------------------------------------------------------------------
// Keys and service auth
// ---------------------------------------------------------------------------

pub fn p256_public_jwk(key: &VerifyingKey) -> Value {
    let point = key.to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
    })
}

pub fn p256_to_pem(key: &SigningKey) -> String {
    SecretKey::from_slice(&key.to_bytes())
        .expect("p256 secret")
        .to_pkcs8_pem(LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

/// `did:key:zDn…` of a P-256 key, as published in `Multikey` verification methods.
fn did_key(key: &PublicKey) -> String {
    encode_p256_did_key(key)
}

/// An ES256 atproto service-auth JWT (`iss`, `aud`, `lxm`, 60 s), as a PDS mints it.
pub fn mint_es256_service_jwt(key: &SigningKey, iss: &str, aud: &str, lxm: &str) -> String {
    let now = Utc::now().timestamp();
    let encode = |value: Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let signing_input = format!(
        "{}.{}",
        encode(json!({"alg": "ES256", "typ": "JWT", "kid": format!("{iss}#atproto")})),
        encode(json!({
            "iss": iss, "aud": aud, "lxm": lxm, "iat": now, "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
        })),
    );
    let signature: Signature = key.sign(signing_input.as_bytes());
    let signature = signature.normalize_s().unwrap_or(signature);
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn space_signer(key: &SigningKey) -> SpaceSigningKey {
    SpaceSigningKey::P256 {
        signing_key: key.clone(),
        kid: ATPROTO_KEY_ID.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// DID directory
// ---------------------------------------------------------------------------

/// Every published DID document (accounts, PDSes' accounts, DSes), served by
/// each PDS's `com.atproto.identity.resolveDid`.
#[derive(Clone, Default)]
pub struct DidDirectory(Arc<RwLock<BTreeMap<String, Value>>>);

impl DidDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, did: &str, document: Value) {
        self.0.write().unwrap().insert(did.to_owned(), document);
    }

    pub fn document(&self, did: &str) -> Option<Value> {
        self.0.read().unwrap().get(did).cloned()
    }

    /// `did`'s document parsed the way the client and the DS parse it.
    fn parsed(&self, did: &str) -> Option<DidDocument> {
        let document = self.document(did)?;
        DidDocument::parse_json(did, &serde_json::to_vec(&document).ok()?).ok()
    }

    /// Token verification resolves the issuer from its published document only.
    fn resolver(&self, did: &str) -> StaticDidResolver {
        let resolver = StaticDidResolver::new();
        if let Some(document) = self.parsed(did) {
            resolver.insert(document);
        }
        resolver
    }
}

// ---------------------------------------------------------------------------
// Loopback Spaces PDS
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Record {
    value: Value,
    dagcbor: Vec<u8>,
    cid: String,
}

#[derive(Clone, Default)]
struct Repo {
    records: BTreeMap<(String, String), Record>,
    hash: LtHash,
    rev_micros: u64,
    ops: Vec<Value>,
}

struct Account {
    key: SigningKey,
    kem: SecretKey,
}

#[derive(Default)]
struct World {
    accounts: BTreeMap<String, Account>,
    sessions: BTreeMap<String, String>,
    /// Public repo records: `(repo, collection, rkey)`.
    public: BTreeMap<(String, String, String), Record>,
    /// Space repos: `(space, writer)`.
    repos: BTreeMap<(String, String), Repo>,
    /// Uploaded, not yet committed blobs: `(account, cid)`.
    staged_blobs: BTreeMap<(String, String), Vec<u8>>,
    /// Blobs committed into a Space: `(space, repo, cid)`.
    space_blobs: BTreeMap<(String, String, String), Vec<u8>>,
    spent_delegations: BTreeSet<String>,
    /// Revoked credential `jti` -> expiry (seconds).
    revoked: BTreeMap<String, u64>,
    deleted_spaces: BTreeSet<String>,
    sequence: u64,
}

impl World {
    fn next(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }
}

struct Pds {
    base_url: String,
    supports_spaces: bool,
    directory: DidDirectory,
    http: reqwest::Client,
    world: Mutex<World>,
}

/// A loopback ATProto PDS. `supports_spaces == false` is a pre-Spaces PDS:
/// every `com.atproto.space.*` answers 501 `XRPCNotSupported` (`I15`).
pub struct SpacesPds {
    pub pds_did: String,
    pub base_url: String,
    inner: Arc<Pds>,
}

/// A validated `applyWrites`, visible only after [`Pds::commit`].
struct StagedWrite {
    space: SpaceUri,
    repo: String,
    base_micros: u64,
    next: Repo,
    results: Vec<Value>,
}

type Reply = Result<Response, Response>;

impl SpacesPds {
    pub async fn start(pds_did: &str, supports_spaces: bool, directory: DidDirectory) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Pds {
            base_url: base_url.clone(),
            supports_spaces,
            directory,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            world: Mutex::new(World::default()),
        });
        let app = Router::new().fallback(handle).with_state(inner.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            pds_did: pds_did.to_owned(),
            base_url,
            inner,
        }
    }

    /// Hosts `did` here: its `#atproto` key, a fresh `#atproto_kem` key and the
    /// OAuth session `oauth_token`. Publishes its DID document and returns its
    /// `#atproto_kem` `did:key`.
    pub fn add_account(&self, did: &str, key: SigningKey, oauth_token: &str) -> String {
        let kem = SecretKey::random(&mut rand::rngs::OsRng);
        let kem_did_key = did_key(&kem.public_key());
        let multikey = |did_key: &str| did_key.trim_start_matches("did:key:").to_owned();
        self.inner.directory.publish(
            did,
            json!({
                "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
                "id": did,
                "verificationMethod": [
                    {"id": format!("{did}#atproto"), "type": "Multikey", "controller": did,
                     "publicKeyMultibase": multikey(&did_key(&PublicKey::from(key.verifying_key())))},
                    {"id": format!("{did}#atproto_kem"), "type": "Multikey", "controller": did,
                     "publicKeyMultibase": multikey(&kem_did_key)},
                ],
                "service": [{"id": "#atproto_pds", "type": "AtprotoPersonalDataServer",
                             "serviceEndpoint": self.base_url}],
            }),
        );
        let mut world = self.inner.world.lock().unwrap();
        world
            .sessions
            .insert(oauth_token.to_owned(), did.to_owned());
        world.accounts.insert(did.to_owned(), Account { key, kem });
        kem_did_key
    }

    /// Another OAuth session (e.g. a second device's sign-in) for a hosted account.
    pub fn add_session(&self, did: &str, oauth_token: &str) {
        let mut world = self.inner.world.lock().unwrap();
        assert!(world.accounts.contains_key(did), "{did} is not hosted here");
        world
            .sessions
            .insert(oauth_token.to_owned(), did.to_owned());
    }

    /// Writes a public repo record as its account would (e.g. a declaration).
    pub fn put_record(&self, repo: &str, collection: &str, rkey: &str, value: Value) {
        let record = record(&value).expect("valid atproto record");
        self.inner.world.lock().unwrap().public.insert(
            (repo.to_owned(), collection.to_owned(), rkey.to_owned()),
            record,
        );
    }

    /// A public repo record's value, if present.
    pub fn record(&self, repo: &str, collection: &str, rkey: &str) -> Option<Value> {
        self.inner
            .world
            .lock()
            .unwrap()
            .public
            .get(&(repo.to_owned(), collection.to_owned(), rkey.to_owned()))
            .map(|record| record.value.clone())
    }

    /// Committed `(rkey, value)` of `collection` in `repo`'s repo of `space`.
    pub fn space_records(&self, space: &str, repo: &str, collection: &str) -> Vec<(String, Value)> {
        self.inner
            .world
            .lock()
            .unwrap()
            .repos
            .get(&(space.to_owned(), repo.to_owned()))
            .map(|repo| {
                repo.records
                    .iter()
                    .filter(|((c, _), _)| c == collection)
                    .map(|((_, rkey), record)| (rkey.clone(), record.value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `repo`'s current commit in `space`: `(rev, LtHash commitment)`.
    pub fn space_commit(&self, space: &str, repo: &str) -> Option<(String, [u8; 32])> {
        self.inner
            .world
            .lock()
            .unwrap()
            .repos
            .get(&(space.to_owned(), repo.to_owned()))
            .map(|repo| (tid(repo.rev_micros, 0), repo.hash.commitment()))
    }

    pub fn space_deleted(&self, space: &str) -> bool {
        self.inner
            .world
            .lock()
            .unwrap()
            .deleted_spaces
            .contains(space)
    }
}

async fn handle(
    State(pds): State<Arc<Pds>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(nsid) = uri.path().strip_prefix("/xrpc/") else {
        return err(404, "NotFound", uri.path());
    };
    let params = match query_params(uri.query().unwrap_or_default()) {
        Ok(params) => params,
        Err(reply) => return reply,
    };
    if nsid.starts_with("com.atproto.space.") && !pds.supports_spaces {
        return err(
            501,
            "XRPCNotSupported",
            "ATProto Spaces not supported on this PDS",
        );
    }
    let reply = match (method.as_str(), nsid) {
        ("POST", "com.atproto.space.applyWrites") => pds.apply_writes(&headers, &body).await,
        ("POST", "com.atproto.space.deleteRecord") => {
            pds.delete_space_record(&headers, &body).await
        }
        _ => pds.handle_sync(&method, nsid, &params, &headers, &body),
    };
    reply.unwrap_or_else(|reply| reply)
}

impl Pds {
    fn handle_sync(
        &self,
        method: &Method,
        nsid: &str,
        params: &BTreeMap<String, String>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Reply {
        let now = now_secs();
        match (method.as_str(), nsid) {
            ("GET", "com.atproto.identity.resolveDid") => {
                let did = required(params, "did")?;
                match self.directory.document(did) {
                    Some(document) => Ok(ok(json!({ "didDoc": document }))),
                    None => Err(err(404, "DidNotFound", did)),
                }
            }
            ("POST", "com.atproto.repo.putRecord") => self.put_record(headers, body),
            ("GET", "com.atproto.repo.getRecord") => self.get_record(params),
            ("GET", "com.atproto.repo.listRecords") => self.list_records(params),
            ("POST", "com.atproto.repo.deleteRecord") => self.delete_record(headers, body),
            ("POST", "com.atproto.repo.uploadBlob") => self.upload_blob(headers, body),
            // Staged and Space-scoped blobs never enter public blob storage (Gate 10).
            ("GET", "com.atproto.sync.getBlob") => Err(err(404, "BlobNotFound", "no public blobs")),
            ("GET", "com.atproto.server.getServiceAuth") => self.service_auth(headers, params),
            ("GET", "com.atproto.space.getSpace") => self.get_space(headers, params),
            ("GET", "com.atproto.space.getDelegationToken") => {
                self.delegation_token(headers, params, now)
            }
            ("POST", "com.atproto.space.getSpaceCredential") => self.space_credential(body, now),
            ("GET", "com.atproto.space.listSpaces") => self.list_spaces(headers),
            (
                "GET",
                "com.atproto.space.getRecord"
                | "com.atproto.space.listRecords"
                | "com.atproto.space.listRepoOps"
                | "com.atproto.space.getRepo"
                | "com.atproto.space.getLatestCommit"
                | "com.atproto.space.getBlob",
            ) => self.read(nsid, params, headers, now),
            ("POST", "com.atproto.space.notifyCredentialRevoked") => {
                self.credentials_revoked(headers, body, now)
            }
            ("POST", "com.atproto.space.notifySpaceDeleted") => {
                self.space_deleted(headers, body, now)
            }
            _ => Err(err(501, "MethodNotImplemented", nsid)),
        }
    }

    /// The account of the request's OAuth session.
    fn session(&self, headers: &HeaderMap) -> Result<String, Response> {
        let token = header_value(headers, header::AUTHORIZATION.as_str())?
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| err(401, "AuthMissing", "OAuth session required"))?;
        self.world
            .lock()
            .unwrap()
            .sessions
            .get(token)
            .cloned()
            .ok_or_else(|| err(401, "InvalidToken", "unknown OAuth session"))
    }

    fn put_record(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let account = self.session(headers)?;
        let body = parse(body)?;
        let repo = text(&body, "repo")?;
        if repo != account {
            return Err(err(403, "Forbidden", "repo must be the session account"));
        }
        let key = (
            repo.to_owned(),
            text(&body, "collection")?.to_owned(),
            text(&body, "rkey")?.to_owned(),
        );
        let record = record(
            body.get("record")
                .ok_or_else(|| err(400, "InvalidRequest", "record missing"))?,
        )?;
        let mut world = self.world.lock().unwrap();
        check_swap(&body, world.public.get(&key))?;
        let reply = json!({
            "uri": format!("at://{}/{}/{}", key.0, key.1, key.2),
            "cid": record.cid,
        });
        world.public.insert(key, record);
        Ok(ok(reply))
    }

    fn get_record(&self, params: &BTreeMap<String, String>) -> Reply {
        let key = (
            required(params, "repo")?.to_owned(),
            required(params, "collection")?.to_owned(),
            required(params, "rkey")?.to_owned(),
        );
        let world = self.world.lock().unwrap();
        let record = world
            .public
            .get(&key)
            .ok_or_else(|| err(404, "RecordNotFound", &key.2))?;
        Ok(ok(json!({
            "uri": format!("at://{}/{}/{}", key.0, key.1, key.2),
            "cid": record.cid,
            "value": record.value,
        })))
    }

    fn list_records(&self, params: &BTreeMap<String, String>) -> Reply {
        let repo = required(params, "repo")?;
        let collection = required(params, "collection")?;
        let limit = limit(params, 50)?;
        let reverse = params.get("reverse").map(String::as_str) == Some("true");
        let cursor = params.get("cursor");
        let world = self.world.lock().unwrap();
        let mut matching: Vec<_> = world
            .public
            .iter()
            .filter(|((r, c, rkey), _)| {
                r == repo
                    && c == collection
                    && cursor.is_none_or(|cursor| {
                        if reverse {
                            rkey < cursor
                        } else {
                            rkey > cursor
                        }
                    })
            })
            .collect();
        if reverse {
            matching.reverse();
        }
        let more = matching.len() > limit;
        matching.truncate(limit);
        let next = more.then(|| matching.last().map(|((_, _, rkey), _)| rkey.clone()));
        let records: Vec<Value> = matching
            .into_iter()
            .map(|((r, c, rkey), record)| {
                json!({"uri": format!("at://{r}/{c}/{rkey}"), "cid": record.cid, "value": record.value})
            })
            .collect();
        Ok(ok(page(records, next.flatten())))
    }

    fn delete_record(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let account = self.session(headers)?;
        let body = parse(body)?;
        let repo = text(&body, "repo")?;
        if repo != account {
            return Err(err(403, "Forbidden", "repo must be the session account"));
        }
        let key = (
            repo.to_owned(),
            text(&body, "collection")?.to_owned(),
            text(&body, "rkey")?.to_owned(),
        );
        let mut world = self.world.lock().unwrap();
        check_swap(&body, world.public.get(&key))?;
        world.public.remove(&key);
        Ok(ok(json!({})))
    }

    fn upload_blob(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let account = self.session(headers)?;
        let cid = blob_cid(body);
        let mime = header_value(headers, header::CONTENT_TYPE.as_str())?
            .unwrap_or("application/octet-stream")
            .to_owned();
        self.world
            .lock()
            .unwrap()
            .staged_blobs
            .insert((account, cid.clone()), body.to_vec());
        Ok(ok(json!({"blob": {
            "$type": "blob", "ref": {"$link": cid}, "mimeType": mime, "size": body.len(),
        }})))
    }

    /// `com.atproto.server.getServiceAuth`: a service JWT issued by the session
    /// account, signed with its `#atproto` key.
    fn service_auth(&self, headers: &HeaderMap, params: &BTreeMap<String, String>) -> Reply {
        let account = self.session(headers)?;
        if params.get("iss").is_some_and(|iss| iss != &account) {
            return Err(err(
                400,
                "InvalidRequest",
                "iss must be the session account",
            ));
        }
        let aud = required(params, "aud")?;
        let lxm = required(params, "lxm")?;
        let world = self.world.lock().unwrap();
        let key = &world.accounts[&account].key;
        Ok(ok(
            json!({ "token": mint_es256_service_jwt(key, &account, aud, lxm) }),
        ))
    }

    fn get_space(&self, headers: &HeaderMap, params: &BTreeMap<String, String>) -> Reply {
        // The eligibility probe: a Spaces PDS rejects the parameterless call as a bad request.
        if !params.contains_key("space") {
            return Err(err(400, "InvalidRequest", "space required"));
        }
        let account = self.session(headers)?;
        let space = space_uri(params.get("space").map(String::as_str))?;
        if self
            .world
            .lock()
            .unwrap()
            .deleted_spaces
            .contains(&space.raw)
        {
            return Err(err(410, "SpaceDeleted", &space.raw));
        }
        if space.space_type == MAILBOX && space.authority == account && space.rkey == "self" {
            return Ok(ok(json!({
                "uri": space.raw,
                "policy": {"$type": "com.atproto.space.policy#ownerOnly", "owner": account},
            })));
        }
        Err(err(
            404,
            "SpaceNotFound",
            "this PDS does not host that Space",
        ))
    }

    fn delegation_token(
        &self,
        headers: &HeaderMap,
        params: &BTreeMap<String, String>,
        now: u64,
    ) -> Reply {
        let account = self.session(headers)?;
        let space = space_uri(params.get("space").map(String::as_str))?;
        let mut world = self.world.lock().unwrap();
        let claims = SpaceTokenClaims {
            iss: account.clone(),
            aud: Some(format!("{}#atproto_pds", space.authority)),
            sub: space.raw,
            iat: now,
            exp: now + DELEGATION_MAX_LIFETIME_SECS,
            jti: format!("delegation-{}", world.next()),
            cnf_kid: None,
        };
        let token = mint_space_token(
            SpaceTokenKind::Delegation,
            &space_signer(&world.accounts[&account].key),
            &claims,
        )
        .map_err(|e| err(500, "InternalServerError", e))?;
        Ok(ok(json!({ "token": token })))
    }

    /// The personal-mailbox Space authority: only the owner's delegation earns a credential.
    fn space_credential(&self, body: &[u8], now: u64) -> Reply {
        let body = parse(body)?;
        let space = space_uri(body["space"].as_str())?;
        let kid = text(&body, "credentialKid")?;
        decode_p256_did_key(kid).map_err(|e| err(400, "InvalidRequest", e))?;
        if space.space_type != MAILBOX
            || space.rkey != "self"
            || !self
                .world
                .lock()
                .unwrap()
                .accounts
                .contains_key(&space.authority)
        {
            return Err(err(
                404,
                "SpaceNotFound",
                "not a Space this PDS is authority of",
            ));
        }
        let delegation = complete(verify_space_token(
            SpaceTokenKind::Delegation,
            text(&body, "delegationToken")?,
            &self.directory.resolver(&space.authority),
            now,
        ))
        .map_err(|e| err(401, "InvalidDelegationToken", e))?;
        if delegation.iss != space.authority {
            return Err(err(
                403,
                "UserNotAuthorized",
                "only the owner reads a personal mailbox",
            ));
        }
        if delegation.sub != space.raw || delegation.exp <= now {
            return Err(err(
                401,
                "InvalidDelegationToken",
                "delegation Space/expiry mismatch",
            ));
        }
        let mut world = self.world.lock().unwrap();
        if !world
            .spent_delegations
            .insert(format!("{}:{}", delegation.iss, delegation.jti))
        {
            return Err(err(
                401,
                "InvalidDelegationToken",
                "replayed delegation jti",
            ));
        }
        let claims = SpaceTokenClaims {
            iss: space.authority.clone(),
            sub: space.raw,
            aud: None,
            iat: now,
            exp: now + CREDENTIAL_DEFAULT_LIFETIME_SECS,
            jti: format!("credential-{}", world.next()),
            cnf_kid: Some(kid.to_owned()),
        };
        let credential = mint_space_token(
            SpaceTokenKind::Credential,
            &space_signer(&world.accounts[&space.authority].key),
            &claims,
        )
        .map_err(|e| err(500, "InternalServerError", e))?;
        let expires_at = chrono::DateTime::from_timestamp(claims.exp as i64, 0)
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
        Ok(ok(
            json!({ "credential": credential, "expiresAt": expires_at }),
        ))
    }

    fn list_spaces(&self, headers: &HeaderMap) -> Reply {
        let account = self.session(headers)?;
        let world = self.world.lock().unwrap();
        let spaces: Vec<Value> = world
            .repos
            .iter()
            .filter(|((space, repo), state)| {
                repo == &account && !state.ops.is_empty() && !world.deleted_spaces.contains(space)
            })
            .map(|((space, _), _)| json!({ "uri": space }))
            .collect();
        Ok(ok(json!({ "spaces": spaces })))
    }

    async fn delete_space_record(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let body = parse(body)?;
        let delete = json!({"space": body["space"], "repo": body["repo"], "writes": [{
            "$type": "com.atproto.space.applyWrites#delete",
            "collection": body["collection"], "rkey": body["rkey"],
        }]});
        self.apply_writes(headers, &serde_json::to_vec(&delete).unwrap())
            .await
    }

    async fn apply_writes(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let account = self.session(headers)?;
        let body = parse(body)?;
        let staged = self.stage_writes(&account, &body)?;
        if staged.space.space_type == CONVERSATION {
            self.notify_write(&staged).await?;
        }
        self.commit(staged)
    }

    fn stage_writes(&self, account: &str, body: &Value) -> Result<StagedWrite, Response> {
        let space = space_uri(body["space"].as_str())?;
        if text(body, "repo")? != account {
            return Err(err(403, "Forbidden", "repo must be the session account"));
        }
        match space.space_type.as_str() {
            CONVERSATION => {}
            MAILBOX if space.authority == account && space.rkey == "self" => {}
            _ => return Err(err(403, "Forbidden", "no write authority for this Space")),
        }
        let writes = body["writes"]
            .as_array()
            .ok_or_else(|| err(400, "InvalidRequest", "writes missing"))?;
        let world = self.world.lock().unwrap();
        if world.deleted_spaces.contains(&space.raw) {
            return Err(err(410, "SpaceDeleted", &space.raw));
        }
        let current = world
            .repos
            .get(&(space.raw.clone(), account.to_owned()))
            .cloned()
            .unwrap_or_default();
        let base_micros = current.rev_micros;
        // Strictly monotonic per repo, as the authority's notifyWrite requires.
        let rev_micros = now_micros().max(base_micros + 1);
        let rev = tid(rev_micros, 0);
        let mut next = current;
        next.rev_micros = rev_micros;
        let mut results = Vec::with_capacity(writes.len());
        for (index, write) in writes.iter().enumerate() {
            let collection = text(write, "collection")?;
            let rkey = write["rkey"]
                .as_str()
                .map_or_else(|| tid(rev_micros, index as u64 + 1), str::to_owned);
            let uri = space
                .record_uri(account, collection, &rkey)
                .map_err(|e| err(400, "InvalidRequest", e))?;
            let key = (collection.to_owned(), rkey);
            let previous = next.records.get(&key).map(|record| record.cid.clone());
            if write
                .get("swapRecord")
                .is_some_and(|swap| swap.as_str() != previous.as_deref())
            {
                return Err(err(400, "InvalidSwap", uri));
            }
            let action = text(write, "$type")?.rsplit('#').next().unwrap_or_default();
            let written = match (action, &previous) {
                ("create", Some(_)) => return Err(err(400, "RecordAlreadyExists", uri)),
                ("update" | "delete", None) => return Err(err(400, "RecordNotFound", uri)),
                ("create" | "update", _) => {
                    Some(record(write.get("value").ok_or_else(|| {
                        err(400, "InvalidRequest", "write value missing")
                    })?)?)
                }
                ("delete", _) => None,
                _ => {
                    return Err(err(
                        400,
                        "InvalidRequest",
                        format!("unsupported write {action}"),
                    ))
                }
            };
            if let Some(old) = next.records.remove(&key) {
                mix(&mut next.hash, &key, &old, false);
            }
            let mut result =
                json!({ "$type": format!("com.atproto.space.applyWrites#{action}Result") });
            let cid = written.as_ref().map(|record| record.cid.clone());
            if let Some(record) = written {
                mix(&mut next.hash, &key, &record, true);
                result["uri"] = uri.into();
                result["cid"] = record.cid.clone().into();
                next.records.insert(key.clone(), record);
            }
            next.ops.push(
                json!({"collection": key.0, "rkey": key.1, "rev": rev, "cid": cid, "prev": previous}),
            );
            results.push(result);
        }
        Ok(StagedWrite {
            space,
            repo: account.to_owned(),
            base_micros,
            next,
            results,
        })
    }

    /// `com.atproto.space.notifyWrite` to the Space authority, service-authenticated
    /// by the writer; a refusal is the write's answer.
    async fn notify_write(&self, staged: &StagedWrite) -> Result<(), Response> {
        let endpoint = self
            .directory
            .parsed(&staged.space.authority)
            .and_then(|document| document.service_endpoint("#atproto_mls").map(str::to_owned))
            .ok_or_else(|| err(502, "UpstreamFailure", "Space authority has no endpoint"))?;
        let token = {
            let world = self.world.lock().unwrap();
            mint_es256_service_jwt(
                &world.accounts[&staged.repo].key,
                &staged.repo,
                &staged.space.authority,
                "com.atproto.space.notifyWrite",
            )
        };
        let response = self
            .http
            .post(format!("{endpoint}/xrpc/com.atproto.space.notifyWrite"))
            .bearer_auth(token)
            .json(&json!({
                "space": staged.space.raw,
                "repo": staged.repo,
                "repoRev": tid(staged.next.rev_micros, 0),
                "data": {"$bytes": STANDARD.encode(staged.next.hash.commitment())},
            }))
            .send()
            .await
            .map_err(|e| err(502, "UpstreamFailure", e))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.bytes().await.unwrap_or_default();
        Err(Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap())
    }

    fn commit(&self, staged: StagedWrite) -> Reply {
        let mut world = self.world.lock().unwrap();
        let key = (staged.space.raw.clone(), staged.repo.clone());
        if world.repos.get(&key).map_or(0, |repo| repo.rev_micros) != staged.base_micros {
            // The authority accepted a commitment over a base this repo no longer has.
            return Err(err(
                409,
                "InvalidSwap",
                "repo advanced while the authority was notified",
            ));
        }
        for record in staged.next.records.values() {
            for cid in blob_links(&record.value) {
                if let Some(bytes) = world
                    .staged_blobs
                    .remove(&(staged.repo.clone(), cid.clone()))
                {
                    world
                        .space_blobs
                        .insert((key.0.clone(), key.1.clone(), cid), bytes);
                }
            }
        }
        world.repos.insert(key, staged.next);
        Ok(ok(json!({ "results": staged.results })))
    }

    /// A credential-bound read, direct or relayed by a DS: the PoP-signed
    /// credential comes from the Space authority's `#atproto` key and names the
    /// writer as audience; MACs use the writer's `#atproto_kem` secret.
    fn read(
        &self,
        nsid: &str,
        params: &BTreeMap<String, String>,
        headers: &HeaderMap,
        now: u64,
    ) -> Reply {
        let space = space_uri(params.get("space").map(String::as_str))?;
        let writer = required(params, "repo")?;
        let authorization =
            header_value(headers, header::AUTHORIZATION.as_str())?.unwrap_or_default();
        let jwt = authorization
            .strip_prefix("Atproto-Space-Credential ")
            .ok_or_else(|| err(401, "AuthRequired", "Space credential required"))?;
        let claims = complete(verify_space_token(
            SpaceTokenKind::Credential,
            jwt,
            &self.directory.resolver(&space.authority),
            now,
        ))
        .map_err(|e| err(401, "InvalidSpaceCredential", e))?;
        if claims.iss != space.authority || claims.sub != space.raw || claims.exp <= now {
            return Err(err(
                401,
                "InvalidSpaceCredential",
                "credential binding mismatch or expired",
            ));
        }
        let proof =
            verify_credential_request(headers, claims.cnf_kid.as_deref().unwrap_or_default(), now)
                .map_err(|e| err(401, "BadSpaceSignature", e))?;
        if proof.credential_jwt != jwt || proof.audience_did != writer {
            return Err(err(
                401,
                "BadSpaceSignature",
                "Atproto-Space-Audience must be the writer",
            ));
        }
        let world = self.world.lock().unwrap();
        if world.revoked.contains_key(&claims.jti) {
            return Err(err(
                401,
                "CredentialRevoked",
                "credential revoked by the Space authority",
            ));
        }
        if world.deleted_spaces.contains(&space.raw) {
            return Err(err(410, "SpaceDeleted", &space.raw));
        }
        let Some(account) = world.accounts.get(writer) else {
            return Err(err(404, "RepoNotFound", writer));
        };
        if space.space_type == MAILBOX && (writer != space.authority || space.rkey != "self") {
            return Err(err(
                403,
                "Forbidden",
                "a personal mailbox holds only its owner's repo",
            ));
        }
        let empty = Repo::default();
        let repo = world
            .repos
            .get(&(space.raw.clone(), writer.to_owned()))
            .unwrap_or(&empty);
        let want = header_value(headers, SPACE_WANT_MAC_HEADER_NAME)?;
        let rev = tid(repo.rev_micros, 0);
        let data = repo.hash.commitment();
        let commit = json!({"space": space.raw, "repo": writer, "ver": 1, "rev": rev, "data": {"$bytes": STANDARD.encode(data)}});
        match nsid {
            "com.atproto.space.getRecord" => {
                let collection = required(params, "collection")?;
                let rkey = required(params, "rkey")?;
                let record = repo
                    .records
                    .get(&(collection.to_owned(), rkey.to_owned()))
                    .ok_or_else(|| err(404, "RecordNotFound", rkey))?;
                let uri = space
                    .record_uri(writer, collection, rkey)
                    .map_err(|e| err(400, "InvalidRequest", e))?;
                let secret = shared_secret(&account.kem, want, RECORD_MAC_TYPE)?;
                let (_, cid) = multibase::decode(&record.cid)
                    .map_err(|e| err(500, "InternalServerError", e))?;
                let mac = compute_record_mac(&secret, &uri, &cid)
                    .map_err(|e| err(500, "InternalServerError", e))?;
                Ok(with_mac(
                    ok(json!({"uri": uri, "cid": record.cid, "value": record.value})),
                    format_record_mac_header(&mac),
                ))
            }
            "com.atproto.space.listRecords" => {
                let collection = params.get("collection");
                let reverse = params.get("reverse").map(String::as_str) == Some("true");
                let mut matching: Vec<_> = repo
                    .records
                    .iter()
                    .filter(|((c, rkey), _)| {
                        let path = format!("{c}/{rkey}");
                        collection.is_none_or(|wanted| c == wanted)
                            && params.get("cursor").is_none_or(|cursor| {
                                if reverse {
                                    &path < cursor
                                } else {
                                    &path > cursor
                                }
                            })
                    })
                    .collect();
                if reverse {
                    matching.reverse();
                }
                let limit = limit(params, 50)?;
                let more = matching.len() > limit;
                matching.truncate(limit);
                let cursor = more
                    .then(|| matching.last().map(|((c, rkey), _)| format!("{c}/{rkey}")))
                    .flatten();
                let exclude = params.get("excludeValues").map(String::as_str) == Some("true");
                let records: Vec<Value> = matching
                    .into_iter()
                    .map(|((collection, rkey), record)| {
                        let mut item =
                            json!({"collection": collection, "rkey": rkey, "cid": record.cid});
                        if !exclude {
                            item["value"] = record.value.clone();
                        }
                        item
                    })
                    .collect();
                Ok(ok(page(records, cursor)))
            }
            "com.atproto.space.getBlob" => {
                let cid = required(params, "cid")?;
                let bytes = world
                    .space_blobs
                    .get(&(space.raw.clone(), writer.to_owned(), cid.to_owned()))
                    .ok_or_else(|| err(404, "BlobNotFound", cid))?;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(bytes.clone()))
                    .unwrap())
            }
            _ => {
                // getRepo, getLatestCommit, listRepoOps: commit MACs.
                let secret = shared_secret(&account.kem, want, COMMIT_MAC_TYPE)?;
                let mac = format_commit_mac_header(
                    &compute_commit_mac(&secret, &space.raw, writer, &rev, &data)
                        .map_err(|e| err(500, "InternalServerError", e))?,
                );
                if nsid == "com.atproto.space.getRepo" {
                    let entries: Vec<StarRecordEntry> = repo
                        .records
                        .iter()
                        .map(|((collection, rkey), record)| StarRecordEntry {
                            path: format!("{collection}/{rkey}"),
                            record_dagcbor: record.dagcbor.clone(),
                        })
                        .collect();
                    let body = write_star_repo(&space.raw, writer, &rev, &data, &entries)
                        .map_err(|e| err(500, "InternalServerError", e))?;
                    let star = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.atproto.star")
                        .body(Body::from(body))
                        .unwrap();
                    return Ok(with_mac(star, mac));
                }
                if nsid == "com.atproto.space.getLatestCommit" {
                    return Ok(with_mac(ok(json!({ "commit": commit })), mac));
                }
                let ops: Vec<&Value> = repo
                    .ops
                    .iter()
                    .filter(|op| {
                        params.get("since").is_none_or(|since| {
                            op["rev"].as_str().is_some_and(|rev| rev > since.as_str())
                        })
                    })
                    .collect();
                let start = params
                    .get("cursor")
                    .map(|cursor| cursor.parse::<usize>())
                    .transpose()
                    .map_err(|e| err(400, "InvalidRequest", e))?
                    .unwrap_or(0);
                if start > ops.len() {
                    return Err(err(400, "InvalidRequest", "oplog cursor out of range"));
                }
                let end = start.saturating_add(limit(params, 100)?).min(ops.len());
                let exclude = params.get("excludeValues").map(String::as_str) == Some("true");
                let page: Vec<Value> = ops[start..end]
                    .iter()
                    .map(|&op| {
                        let mut op = op.clone();
                        let current = repo.records.get(&(
                            op["collection"].as_str().unwrap_or_default().to_owned(),
                            op["rkey"].as_str().unwrap_or_default().to_owned(),
                        ));
                        // Only the current value is authenticated by the head commitment.
                        if let Some(record) = current
                            .filter(|r| !exclude && op["cid"].as_str() == Some(r.cid.as_str()))
                        {
                            op["value"] = record.value.clone();
                        }
                        op
                    })
                    .collect();
                if end < ops.len() {
                    return Ok(ok(json!({ "ops": page, "cursor": end.to_string() })));
                }
                Ok(with_mac(ok(json!({ "ops": page, "commit": commit })), mac))
            }
        }
    }

    /// Service auth from the Space authority, addressed to a repo DID this PDS hosts.
    fn verify_authority(
        &self,
        headers: &HeaderMap,
        authority: &str,
        lxm: &str,
        now: u64,
    ) -> Result<(), Response> {
        let denied = |why: &str| err(401, "AuthRequired", why);
        let jwt = header_value(headers, header::AUTHORIZATION.as_str())?
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| denied("service auth required"))?;
        let parts: Vec<&str> = jwt.split('.').collect();
        let [header_b64, claims_b64, signature_b64] = parts[..] else {
            return Err(denied("malformed JWT"));
        };
        let decode = |part: &str| {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| denied("malformed JWT"))
        };
        let json = |part: &str| {
            serde_json::from_slice::<Value>(&decode(part)?).map_err(|_| denied("malformed JWT"))
        };
        let (jwt_header, claims) = (json(header_b64)?, json(claims_b64)?);
        let key = self
            .directory
            .parsed(authority)
            .and_then(|document| document.atproto_key)
            .ok_or_else(|| denied("authority has no #atproto key"))?;
        let alg = jwt_header["alg"].as_str().unwrap_or_default();
        if alg != key.expected_alg()
            || !key.verify_raw(
                alg,
                format!("{header_b64}.{claims_b64}").as_bytes(),
                &decode(signature_b64)?,
            )
        {
            return Err(denied("bad service auth signature"));
        }
        let hosted = claims["aud"]
            .as_str()
            .map(|aud| aud.split('#').next().unwrap_or(aud))
            .is_some_and(|did| self.world.lock().unwrap().accounts.contains_key(did));
        if claims["iss"]
            .as_str()
            .map(|iss| iss.split('#').next().unwrap_or(iss))
            != Some(authority)
            || !hosted
            || claims["lxm"].as_str() != Some(lxm)
            || claims["exp"].as_u64().is_none_or(|exp| exp <= now)
        {
            return Err(denied("service auth binding mismatch or expired"));
        }
        Ok(())
    }

    fn credentials_revoked(&self, headers: &HeaderMap, body: &[u8], now: u64) -> Reply {
        let body = parse(body)?;
        let space = space_uri(body["space"].as_str())?;
        self.verify_authority(
            headers,
            &space.authority,
            "com.atproto.space.notifyCredentialRevoked",
            now,
        )?;
        let credentials = body["credentials"]
            .as_array()
            .ok_or_else(|| err(400, "InvalidRequest", "credentials missing"))?;
        let mut revoked = Vec::with_capacity(credentials.len());
        for credential in credentials {
            let exp = chrono::DateTime::parse_from_rfc3339(text(credential, "expiresAt")?)
                .map_err(|e| err(400, "InvalidRequest", e))?;
            revoked.push((
                text(credential, "jti")?.to_owned(),
                exp.timestamp().max(0) as u64,
            ));
        }
        let mut world = self.world.lock().unwrap();
        world.revoked.retain(|_, exp| *exp > now);
        world.revoked.extend(revoked);
        Ok(ok(json!({})))
    }

    /// The authority deleted the Space: drop this host's copy; it is gone for reads and writes.
    fn space_deleted(&self, headers: &HeaderMap, body: &[u8], now: u64) -> Reply {
        let body = parse(body)?;
        let space = space_uri(body["space"].as_str())?;
        self.verify_authority(
            headers,
            &space.authority,
            "com.atproto.space.notifySpaceDeleted",
            now,
        )?;
        let mut world = self.world.lock().unwrap();
        world.repos.retain(|(s, _), _| s != &space.raw);
        world.space_blobs.retain(|(s, _, _), _| s != &space.raw);
        world.deleted_spaces.insert(space.raw);
        Ok(ok(json!({})))
    }
}

/// A list page; the last page carries no `cursor` at all.
fn page(records: Vec<Value>, cursor: Option<String>) -> Value {
    let mut page = json!({ "records": records });
    if let Some(cursor) = cursor {
        page["cursor"] = cursor.into();
    }
    page
}

fn record(value: &Value) -> Result<Record, Response> {
    let invalid =
        |e: &dyn std::fmt::Display| err(400, "InvalidRecord", format!("invalid record: {e}"));
    let typed: catbird_atproto::types::value::Data =
        serde_json::from_value(value.clone()).map_err(|e| invalid(&e))?;
    let dagcbor = serde_ipld_dagcbor::to_vec(&typed).map_err(|e| invalid(&e))?;
    validate_canonical_dagcbor_record(&dagcbor).map_err(|e| invalid(&e))?;
    // Served as written: jacquard re-renders `$bytes` padded, which is not atproto JSON;
    // the CID binds exactly the DAG-CBOR this JSON decodes to.
    Ok(Record {
        value: value.clone(),
        cid: compute_dagcbor_cid(&dagcbor).to_string(),
        dagcbor,
    })
}

/// `swapRecord` compare-and-swap: a CID must match the current record; `null` requires absence.
fn check_swap(body: &Value, current: Option<&Record>) -> Result<(), Response> {
    match body.get("swapRecord") {
        Some(swap) if swap.as_str() != current.map(|record| record.cid.as_str()) => {
            Err(err(400, "InvalidSwap", "swapRecord does not match"))
        }
        _ => Ok(()),
    }
}

/// CIDv1 raw sha2-256, base32: an ATProto blob reference.
fn blob_cid(bytes: &[u8]) -> String {
    let mut cid = vec![1, 0x55, 0x12, 0x20];
    cid.extend_from_slice(&Sha256::digest(bytes));
    multibase::encode(multibase::Base::Base32Lower, cid)
}

fn blob_links(value: &Value) -> Vec<String> {
    match value {
        Value::Object(map) if map.get("$type").and_then(Value::as_str) == Some("blob") => map
            .get("ref")
            .and_then(|r| r["$link"].as_str())
            .map(|cid| vec![cid.to_owned()])
            .unwrap_or_default(),
        Value::Object(map) => map.values().flat_map(blob_links).collect(),
        Value::Array(items) => items.iter().flat_map(blob_links).collect(),
        _ => Vec::new(),
    }
}

fn mix(hash: &mut LtHash, (collection, rkey): &(String, String), record: &Record, add: bool) {
    let cid = record.cid.parse().expect("PDS-minted CID");
    if add {
        hash.add_record(collection, rkey, &cid);
    } else {
        hash.remove_record(collection, rkey, &cid);
    }
}

fn shared_secret(kem: &SecretKey, want: Option<&str>, kind: &str) -> Result<[u8; 32], Response> {
    let want = want.ok_or_else(|| err(400, "BadSpaceMac", "Atproto-Space-Want-Mac required"))?;
    let share = parse_want_mac_header(want, kind).map_err(|e| err(400, "BadSpaceMac", e))?;
    decapsulate_p256(kem, &share).map_err(|e| err(400, "BadSpaceMac", e))
}

/// ATProto TID: 53-bit microseconds, 10-bit clock id, base32-sortable.
fn tid(micros: u64, clock: u64) -> String {
    const S32: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let value = ((micros & ((1 << 53) - 1)) << 10) | (clock & 0x3ff);
    (0..13)
        .rev()
        .map(|i| S32[((value >> (5 * i)) & 31) as usize] as char)
        .collect()
}

fn now_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn now_micros() -> u64 {
    Utc::now().timestamp_micros().max(0) as u64
}

fn space_uri(raw: Option<&str>) -> Result<SpaceUri, Response> {
    SpaceUri::parse(raw.ok_or_else(|| err(400, "InvalidRequest", "space required"))?)
        .map_err(|e| err(400, "InvalidRequest", e))
}

fn query_params(query: &str) -> Result<BTreeMap<String, String>, Response> {
    let mut params = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if params.insert(key.to_string(), value.into_owned()).is_some() {
            return Err(err(
                400,
                "InvalidRequest",
                format!("duplicate query parameter {key}"),
            ));
        }
    }
    Ok(params)
}

fn parse(bytes: &[u8]) -> Result<Value, Response> {
    serde_json::from_slice(bytes).map_err(|e| err(400, "InvalidRequest", e))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, Response> {
    value[field]
        .as_str()
        .ok_or_else(|| err(400, "InvalidRequest", format!("missing {field}")))
}

fn required<'a>(params: &'a BTreeMap<String, String>, field: &str) -> Result<&'a str, Response> {
    params
        .get(field)
        .map(String::as_str)
        .ok_or_else(|| err(400, "InvalidRequest", format!("missing {field}")))
}

fn limit(params: &BTreeMap<String, String>, default: usize) -> Result<usize, Response> {
    let limit = params
        .get("limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| err(400, "InvalidRequest", e))?
        .unwrap_or(default);
    if !(1..=1000).contains(&limit) {
        return Err(err(400, "InvalidRequest", "invalid page limit"));
    }
    Ok(limit)
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, Response> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| err(400, "InvalidRequest", "non-ASCII header"))
        })
        .transpose()?;
    if values.next().is_some() {
        return Err(err(400, "InvalidRequest", format!("duplicate {name}")));
    }
    Ok(value)
}

fn ok(body: Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

fn with_mac(mut response: Response, mac: String) -> Response {
    let headers = response.headers_mut();
    headers.insert(SPACE_MAC_HEADER_NAME, HeaderValue::from_str(&mac).unwrap());
    headers.insert(
        "access-control-expose-headers",
        HeaderValue::from_static("Atproto-Space-Mac"),
    );
    response
}

fn err(status: u16, error: &str, message: impl std::fmt::Display) -> Response {
    (
        StatusCode::from_u16(status).unwrap(),
        Json(json!({ "error": error, "message": message.to_string() })),
    )
        .into_response()
}

/// The DID-document resolver never suspends, so one poll completes token verification.
fn complete<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => unreachable!("static DID resolver suspended"),
    }
}

// ---------------------------------------------------------------------------
// The clean-slate DS process
// ---------------------------------------------------------------------------

pub async fn pg_connect(url: &str) -> Result<PgClient> {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .with_context(|| format!("connect postgres {url}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn pg_admin_url() -> String {
    std::env::var("CLEAN_SLATE_PG_ADMIN_URL")
        .unwrap_or_else(|_| "postgresql://127.0.0.1:5432/postgres".to_string())
}

fn fixture_binary_path() -> PathBuf {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("mls-ds root")
        .join("target/debug/clean_slate_federation_fixture");
    assert!(
        binary.exists(),
        "expected compiled clean_slate_federation_fixture at {}",
        binary.display()
    );
    binary
}

/// One `clean_slate_federation_fixture` (shipping chat, Labyrinth, Space host and
/// group-relay routers plus `/_test/clean-slate/*` hooks) over its own freshly
/// migrated database, dropped with the process.
pub struct CleanSlateDsProcess {
    db_name: String,
    pub db_url: String,
    pub service_did: String,
    pub base_url: String,
    pub signing_key: SigningKey,
    pub receipt_key: SigningKey,
    pub did_document: Value,
    pub pool: PgClient,
    child: Option<Child>,
}

impl CleanSlateDsProcess {
    pub async fn spawn(service_did: &str, s2s_secret: &[u8]) -> Result<Self> {
        let admin = pg_connect(&pg_admin_url())
            .await
            .context("connect postgres admin db")?;
        let db_name = format!("clean_slate_fed_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
            .await
            .with_context(|| format!("create database {db_name}"))?;
        let db_url = format!("postgresql://127.0.0.1:5432/{db_name}");
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let receipt_key = SigningKey::random(&mut rand::rngs::OsRng);
        let mut child = Command::new(fixture_binary_path())
            .env("APP_ENV", "test")
            .env("TEST_DATABASE_URL", &db_url)
            .env("SERVICE_DID", service_did)
            .env("SIGNING_KEY_PEM", p256_to_pem(&signing_key))
            .env("RECEIPT_SIGNING_KEY_PEM", p256_to_pem(&receipt_key))
            .env(
                "FEDERATION_GROUP_RELAY_HMAC_SECRET",
                std::str::from_utf8(s2s_secret).context("S2S secret is UTF-8")?,
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn clean_slate_federation_fixture")?;
        let stdout = child.stdout.take().context("capture child stdout")?;
        let readiness = tokio::task::spawn_blocking(move || -> Result<String> {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line)?;
            Ok(line)
        })
        .await??;
        let ready: Value = serde_json::from_str(readiness.trim())
            .with_context(|| format!("parse fixture readiness JSON: {readiness}"))?;
        let base_url = ready["baseUrl"]
            .as_str()
            .context("missing baseUrl")?
            .to_string();
        let did_document = ready["didDocument"].clone();
        let pool = pg_connect(&db_url).await.context("connect test pool")?;
        Ok(Self {
            db_name,
            db_url,
            service_did: service_did.to_string(),
            base_url,
            signing_key,
            receipt_key,
            did_document,
            pool,
            child: Some(child),
        })
    }

    /// `/_test/clean-slate/register-did`: `did`'s `#atproto` key and service endpoint
    /// (a PDS for accounts, a DS for peers) for this DS's resolvers and Space relays.
    pub async fn register_did(
        &self,
        http: &reqwest::Client,
        did: &str,
        key: &VerifyingKey,
        endpoint_url: &str,
    ) -> Result<()> {
        self.register(
            http,
            json!({"did": did, "p256Jwk": p256_public_jwk(key), "endpointUrl": endpoint_url}),
        )
        .await
    }

    /// Registers `ds` (possibly this one) as a federation peer with its DID document.
    pub async fn register_ds(
        &self,
        http: &reqwest::Client,
        ds: &CleanSlateDsProcess,
    ) -> Result<()> {
        self.register(
            http,
            json!({
                "did": ds.service_did,
                "p256Jwk": p256_public_jwk(ds.signing_key.verifying_key()),
                "endpointUrl": ds.base_url,
                "didDocument": ds.did_document,
                "isDs": true,
            }),
        )
        .await
    }

    async fn register(&self, http: &reqwest::Client, body: Value) -> Result<()> {
        http.post(format!("{}/_test/clean-slate/register-did", self.base_url))
            .json(&body)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("register-did {} on {}", body["did"], self.service_did))?;
        Ok(())
    }
}

impl Drop for CleanSlateDsProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let db_name = self.db_name.clone();
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(async {
                    if let Ok(admin) = pg_connect(&pg_admin_url()).await {
                        let _ = admin
                            .execute(
                                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
                                &[&db_name],
                            )
                            .await;
                        let _ = admin
                            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
                            .await;
                    }
                });
            }
        })
        .join();
    }
}

/// The Space authority `ds` recorded, from the PDS's `notifyWrite`, exactly the
/// commit `pds` serves for `writer`'s repo in `space`.
pub async fn assert_authority_notified(
    ds: &CleanSlateDsProcess,
    pds: &SpacesPds,
    space: &str,
    writer: &str,
) -> Result<()> {
    let (rev, data) = pds
        .space_commit(space, writer)
        .with_context(|| format!("no committed repo for {writer} in {space}"))?;
    let row = ds
        .pool
        .query_one(
            "SELECT repo_rev, data_cid FROM chat.conversation_space_writers \
              WHERE space_uri = $1 AND writer_did = $2",
            &[&space, &writer],
        )
        .await
        .with_context(|| format!("{} has no writer row for {writer}", ds.service_did))?;
    anyhow::ensure!(
        (row.get::<_, String>(0), row.get::<_, Vec<u8>>(1)) == (rev, data.to_vec()),
        "{} must record {writer}'s notified commit in {space}",
        ds.service_did
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Native client platform transport and key store
// ---------------------------------------------------------------------------

/// One exchange the transport carried: method, URL, status, XRPC error name.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub error: Option<String>,
}

struct AccountSession {
    did: String,
    key: SigningKey,
    home_ds_did: String,
    pds_base_url: String,
    pds_token: String,
}

/// The platform transport a native app supplies: its account's PDS OAuth
/// session on PDS requests, scoped service auth (`lxm` = NSID, `aud` = the home
/// DS's `#atproto_mls`) on `blue.catbird.*` requests, and nothing on requests
/// that already authenticate (Space credential presentations). A D1 firewall
/// refuses every origin outside `allowed_origins`; every exchange is recorded.
pub struct ClientTransport {
    allowed_origins: Vec<String>,
    http: reqwest::Client,
    pub blocked_attempts: AtomicUsize,
    chat_bearer_token: Mutex<Option<String>>,
    account: Mutex<Option<AccountSession>>,
    exchanges: Mutex<Vec<Exchange>>,
}

impl ClientTransport {
    pub fn new(allowed_origins: Vec<String>) -> Self {
        Self {
            allowed_origins: allowed_origins
                .into_iter()
                .map(|u| u.trim_end_matches('/').to_string())
                .collect(),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            blocked_attempts: AtomicUsize::new(0),
            chat_bearer_token: Mutex::new(None),
            account: Mutex::new(None),
            exchanges: Mutex::new(Vec::new()),
        }
    }

    /// Signs in as `did` (its `#atproto` `key`, homed on `home_ds_did`, with the PDS
    /// OAuth session `pds_token` on `pds_base_url`).
    pub fn set_account(
        &self,
        did: &str,
        key: SigningKey,
        home_ds_did: &str,
        pds_base_url: &str,
        pds_token: &str,
    ) {
        *self.account.lock().unwrap() = Some(AccountSession {
            did: did.to_owned(),
            key,
            home_ds_did: home_ds_did.to_owned(),
            pds_base_url: pds_base_url.trim_end_matches('/').to_owned(),
            pds_token: pds_token.to_owned(),
        });
    }

    /// A fixed bearer for every `blue.catbird.*` request instead of minted service auth.
    pub fn set_chat_bearer_token(&self, token: String) {
        *self.chat_bearer_token.lock().unwrap() = Some(token);
    }

    pub fn exchanges(&self) -> Vec<Exchange> {
        self.exchanges.lock().unwrap().clone()
    }

    fn assert_allowed(&self, url: &str) -> Result<()> {
        if !self
            .allowed_origins
            .iter()
            .any(|origin| url.starts_with(origin))
        {
            self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("D1 client firewall blocked direct outbound request to {url}");
        }
        Ok(())
    }

    /// The authorization this platform adds to `url`, if any.
    fn authorization(&self, url: &str) -> Option<String> {
        let account = self.account.lock().unwrap();
        let account = account.as_ref();
        if let Some(account) = account.filter(|a| url.starts_with(&a.pds_base_url)) {
            return Some(format!("Bearer {}", account.pds_token));
        }
        let nsid = url.split("/xrpc/").nth(1)?.split('?').next()?;
        if !nsid.starts_with("blue.catbird.") {
            return None;
        }
        if let Some(token) = self.chat_bearer_token.lock().unwrap().clone() {
            return Some(format!("Bearer {token}"));
        }
        let account = account?;
        let home = account.home_ds_did.split('#').next().unwrap_or_default();
        Some(format!(
            "Bearer {}",
            mint_es256_service_jwt(
                &account.key,
                &account.did,
                &format!("{home}#atproto_mls"),
                nsid
            )
        ))
    }

    pub async fn post_json_with_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &Value,
    ) -> Result<(u16, HeaderMap, Vec<u8>)> {
        self.assert_allowed(url)?;
        let mut request = self.http.post(url).json(body);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await?;
        Ok((
            response.status().as_u16(),
            response.headers().clone(),
            response.bytes().await?.to_vec(),
        ))
    }

    pub async fn get_with_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<(u16, HeaderMap, Vec<u8>)> {
        self.assert_allowed(url)?;
        let mut request = self.http.get(url);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = request.send().await?;
        Ok((
            response.status().as_u16(),
            response.headers().clone(),
            response.bytes().await?.to_vec(),
        ))
    }
}

impl PlatformTransport for ClientTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        self.assert_allowed(&request.url)
            .map_err(|e| MLSError::Internal(e.to_string()))?;
        let authorization = (!request
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("authorization")))
        .then(|| self.authorization(&request.url))
        .flatten();
        let http = self.http.clone();
        let (method, url) = (request.method.clone(), request.url.clone());
        let response = std::thread::spawn(move || -> Result<PlatformHttpResponse, MLSError> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(e.to_string()))?;
            runtime.block_on(async move {
                let method = reqwest::Method::from_bytes(request.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(e.to_string()))?;
                let mut builder = http.request(method, &request.url);
                for h in &request.headers {
                    builder = builder.header(&h.name, &h.value);
                }
                if let Some(authorization) = authorization {
                    builder = builder.header("authorization", authorization);
                }
                if let Some(body) = request.body {
                    builder = builder.body(body);
                }
                let response = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|value| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: value.to_string(),
                        })
                    })
                    .collect();
                let body = response
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("transport panic".into()))?;
        let (status, error) = match &response {
            Ok(response) => (
                response.status,
                serde_json::from_slice::<Value>(&response.body)
                    .ok()
                    .and_then(|body| body["error"].as_str().map(str::to_owned)),
            ),
            Err(error) => (0, Some(error.to_string())),
        };
        self.exchanges.lock().unwrap().push(Exchange {
            method,
            url,
            status,
            error,
        });
        response
    }

    fn connect_realtime_stream(&self, url: String, _cursor: Option<i64>) -> Result<(), MLSError> {
        self.assert_allowed(&url)
            .map_err(|e| MLSError::Internal(e.to_string()))
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

/// An app keychain held in memory.
#[derive(Default)]
pub struct MemoryKeyStore {
    keys: Mutex<HashMap<String, Vec<u8>>>,
    dpop: Mutex<HashMap<String, (String, i64)>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn cached_dpop(&self, account_did_hash: &str) -> Option<String> {
        let now_ms = Utc::now().timestamp_millis();
        self.dpop
            .lock()
            .unwrap()
            .get(account_did_hash)
            .and_then(|(token, exp)| (*exp > now_ms).then(|| token.clone()))
    }
}

impl PushKeystore for MemoryKeyStore {
    fn load_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        self.keys
            .lock()
            .unwrap()
            .get(&format!("db:{account_did_hash}"))
            .cloned()
            .ok_or_else(|| MLSError::Internal(format!("missing db key for {account_did_hash}")))
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.keys.lock().unwrap().get(&key_id).cloned())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(self.cached_dpop(&account_did_hash))
    }
}

impl PlatformKeyStore for MemoryKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        Ok(self
            .keys
            .lock()
            .unwrap()
            .entry(format!("db:{account_did_hash}"))
            .or_insert_with(|| {
                let mut key = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut key);
                key
            })
            .clone())
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        Ok(self.keys.lock().unwrap().get(&key_id).cloned())
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.keys.lock().unwrap().insert(key_id, keypair_bytes);
        Ok(())
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        let mut keys = self.keys.lock().unwrap();
        keys.remove(&format!("db:{account_did_hash}"));
        keys.remove(&format!("mls-signer:{account_did_hash}"));
        self.dpop.lock().unwrap().remove(&account_did_hash);
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        Ok(self.cached_dpop(&account_did_hash))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        self.dpop
            .lock()
            .unwrap()
            .insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}
