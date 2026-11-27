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
//! the writer, with `Accept-Signature` answered from the writer's
//! `#atproto_kem` secret; real DAG-CBOR CIDs, LtHash commits, `listRepoOps`
//! replay and STAR `getRepo`. A conversation-Space write commits only after the
//! Space authority accepts the PDS's service-authenticated `notifyRepoUpdate`.
//! `notifyCredentialRevoked` / `notifySpaceDeleted` must carry the authority's
//! service auth. DID documents live in one [`DidDirectory`] (the stand-in for
//! PLC / did:web) that every PDS's `resolveDid` serves.
// The PDS handlers' `Err` is the XRPC error response itself.
#![allow(clippy::result_large_err)]

#[path = "../../../server/tests/common/space_fixtures.rs"]
mod space_fixtures;
pub use space_fixtures::delegation;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    io::{BufRead as _, BufReader, Write as _},
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
use petrel_core::{AtUri, Did, SpaceRef};
use petrel_spaces::{
    compute_dagcbor_cid, decapsulate_p256, decode_p256_did_key, encode_p256_did_key,
    extract_signing_key, mint_credential_token, parse_accept_signature, parse_space_ref,
    sign_commit_mac, sign_record_mac, verify_credential_request, verify_credential_token,
    verify_delegation_token, verify_json_value_for_dag_cbor, write_star_repo, LtHash, MacProfile,
    SigningKeyPair, SpaceDidDocument, SpaceMacHeaders, StaticDidResolver,
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
pub fn did_key(key: &PublicKey) -> String {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    encode_p256_did_key(key.to_encoded_point(true).as_bytes()).expect("fixture P-256 key")
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

fn space_signer(key: &SigningKey) -> SigningKeyPair {
    SigningKeyPair::from_p256_bytes(&key.to_bytes()).expect("fixture P-256 key")
}

// ---------------------------------------------------------------------------
// DID directory
// ---------------------------------------------------------------------------

/// Published test DID documents, shared by the simulated identity authorities and
/// the PDS `com.atproto.identity.resolveDid` endpoint.
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
    fn parsed(&self, did: &str) -> Option<SpaceDidDocument> {
        let document = self.document(did)?;
        let parsed: SpaceDidDocument = serde_json::from_value(document).ok()?;
        (parsed.id.as_str() == did).then_some(parsed)
    }

    /// Token verification resolves the issuer from its published document only.
    fn resolver(&self, did: &str) -> StaticDidResolver {
        let mut resolver = StaticDidResolver::new();
        if let Some(document) = self.parsed(did) {
            resolver.insert_document(document);
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
    typed: petrel_core::Value,
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
    created_spaces: BTreeSet<String>,
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
    public_heads: tokio::sync::Mutex<BTreeMap<String, SignedPublicHead>>,
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
    space: SpaceRef,
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
            public_heads: Default::default(),
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

    pub fn client_transport(&self, home_ds: &str) -> ClientTransport {
        ClientTransport::new(
            vec![home_ds.to_owned(), self.base_url.clone()],
            self.inner.directory.clone(),
        )
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
                             "serviceEndpoint": self.base_url.replacen("http://", "https://", 1)}],
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
            .map(|repo| (tid(repo.rev_micros, 0), repo.hash.digest()))
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
        (
            "GET",
            "com.atproto.sync.getRecord"
            | "com.atproto.sync.getLatestCommit"
            | "com.atproto.sync.getBlocks"
            | "com.atproto.sync.getRepo",
        ) => pds.read_public_repository(nsid, &params).await,
        ("POST", "com.atproto.space.applyWrites") => pds.apply_writes(&headers, &body).await,
        ("POST", "com.atproto.space.deleteRecord") => {
            pds.delete_space_record(&headers, &body).await
        }
        _ => pds.handle_sync(&method, nsid, &params, &headers, &body),
    };
    reply.unwrap_or_else(|reply| reply)
}

/// A writer's signed public repository, maintained alongside its public XRPC records.
struct SignedPublicHead {
    repo: petrel_repo::Repository,
    records: BTreeMap<(String, String), String>,
}

impl SignedPublicHead {
    async fn refresh(
        &mut self,
        current: &BTreeMap<(String, String), Record>,
        signer: &petrel_repo::P256Keypair,
    ) -> Result<()> {
        use petrel_repo::{
            repository::{create_op, update_op},
            RepositoryPath, WriteBatch, WriteOp,
        };
        let mut writes = Vec::new();
        for ((collection, rkey), record) in current {
            match self.records.get(&(collection.clone(), rkey.clone())) {
                Some(cid) if cid == &record.cid => {}
                Some(_) => writes.push(update_op(collection, rkey, &record.typed)?),
                None => writes.push(create_op(collection, rkey, &record.typed)?),
            }
        }
        for (collection, rkey) in self
            .records
            .keys()
            .filter(|key| !current.contains_key(*key))
        {
            writes.push(WriteOp::Delete {
                path: RepositoryPath::new(collection, rkey)?,
            });
        }
        if !writes.is_empty() {
            self.repo = self
                .repo
                .commit_writes(WriteBatch::new(writes)?, signer)
                .await?
                .repository;
            self.records = current
                .iter()
                .map(|(key, r)| (key.clone(), r.cid.clone()))
                .collect();
        }
        Ok(())
    }
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
            ("POST", "com.atproto.repo.createRecord" | "com.atproto.repo.putRecord") => {
                self.write_public_record(nsid, headers, body)
            }
            ("GET", "com.atproto.repo.getRecord") => self.get_record(params),
            ("GET", "com.atproto.repo.listRecords") => self.list_records(params),
            ("POST", "com.atproto.repo.deleteRecord") => self.delete_record(headers, body),
            ("POST", "com.atproto.repo.uploadBlob") => self.upload_blob(headers, body),
            // Staged and Space-scoped blobs never enter public blob storage (Gate 10).
            ("GET", "com.atproto.sync.getBlob") => Err(err(404, "BlobNotFound", "no public blobs")),
            ("GET", "com.atproto.server.getServiceAuth") => self.service_auth(headers, params),
            ("POST", "com.atproto.space.createSpace") => self.create_space(headers, body),
            ("GET", "com.atproto.space.getSpace") => self.get_space(headers, params),
            ("GET", "com.atproto.space.getDelegationToken") => {
                self.delegation_token(headers, params, now)
            }
            ("POST", "com.atproto.space.getSpaceCredential") => {
                self.space_credential(body, now, "credentialKid")
            }
            ("POST", "com.atproto.space.authorizeSpaceSync") => {
                self.space_credential(body, now, "credentialKey")
            }
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

    async fn signed_public_repository(
        &self,
        did: &str,
    ) -> Result<petrel_repo::Repository, Response> {
        let mut heads = self.public_heads.lock().await;
        let (records, key) = {
            let world = self.world.lock().unwrap();
            let account = world
                .accounts
                .get(did)
                .ok_or_else(|| err(404, "RepoNotFound", did))?;
            let records = world
                .public
                .iter()
                .filter(|((repo, _, _), _)| repo == did)
                .map(|((_, c, r), record)| ((c.clone(), r.clone()), record.clone()))
                .collect::<BTreeMap<_, _>>();
            (records, account.key.to_bytes())
        };
        let result: anyhow::Result<petrel_repo::Repository> = async {
            let signer = petrel_repo::P256Keypair::from_bytes(&key.into())?;
            let head = match heads.entry(did.to_owned()) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(SignedPublicHead {
                        repo: petrel_repo::Repository::create(Did::parse(did)?, &signer).await?,
                        records: BTreeMap::new(),
                    })
                }
            };
            head.refresh(&records, &signer).await?;
            Ok(head.repo.clone())
        }
        .await;
        result.map_err(|e| err(500, "RepoProofFailed", e))
    }

    async fn read_public_repository(&self, nsid: &str, params: &BTreeMap<String, String>) -> Reply {
        use petrel_repo::{car::varint::push_varint, BlockSource as _};
        let did = required(params, "did")?;
        let repo = self.signed_public_repository(did).await?;
        let problem = |e: &dyn std::fmt::Display| err(500, "RepoProofFailed", e);
        let car = match nsid {
            "com.atproto.sync.getLatestCommit" => {
                return Ok(ok(json!({
                    "cid": repo.commit().cid.to_string(), "rev": repo.revision().to_string()
                })))
            }
            "com.atproto.sync.getRecord" => {
                let c = required(params, "collection")?;
                let r = required(params, "rkey")?;
                let proof = repo.record_proof(c, r).await.map_err(|e| problem(&e))?;
                if proof.record_cid.is_none() {
                    return Err(err(404, "RecordNotFound", r));
                }
                proof.car().map_err(|e| problem(&e))?
            }
            "com.atproto.sync.getBlocks" => {
                let id = petrel_core::Cid::parse(required(params, "cids")?)
                    .map_err(|e| err(400, "InvalidRequest", e))?;
                let bytes = repo
                    .store()
                    .get_block(&id)
                    .await
                    .map_err(|e| problem(&e))?
                    .ok_or_else(|| err(404, "BlockNotFound", &id))?;
                // getBlocks carries individual blocks in a rootless CAR. Repository
                // exports and inclusion proofs instead carry their signed commit root.
                let header = serde_ipld_dagcbor::to_vec(&json!({"roots": [], "version": 1}))
                    .map_err(|e| problem(&e))?;
                let mut output = Vec::new();
                push_varint(header.len() as u64, &mut output).map_err(|e| problem(&e))?;
                output.extend_from_slice(&header);
                push_varint((id.as_bytes().len() + bytes.len()) as u64, &mut output)
                    .map_err(|e| problem(&e))?;
                output.extend_from_slice(id.as_bytes());
                output.extend_from_slice(&bytes);
                output
            }
            "com.atproto.sync.getRepo" => repo.export_car().await.map_err(|e| problem(&e))?,
            _ => unreachable!("public repository read route"),
        };
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, "application/vnd.ipld.car")
            .body(Body::from(car))
            .expect("CAR response"))
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

    fn write_public_record(&self, nsid: &str, headers: &HeaderMap, body: &[u8]) -> Reply {
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
        let previous = world.public.get(&key);
        if nsid == "com.atproto.repo.createRecord" && previous.is_some() {
            return Err(err(400, "InvalidRequest", "record already exists"));
        }
        check_swap(&body, previous)?;
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

    fn create_space(&self, headers: &HeaderMap, body: &[u8]) -> Reply {
        let account = self.session(headers)?;
        let body = parse(body)?;
        if body["policy"]["$type"] != "com.atproto.personalspace.policy" {
            return Err(err(
                400,
                "UnsupportedPolicy",
                "personal mailbox policy required",
            ));
        }
        let kind = text(&body, "spaceType")?;
        let skey = text(&body, "skey")?;
        if kind != MAILBOX || skey != "self" {
            return Err(err(
                400,
                "InvalidRequest",
                "expected personal Labyrinth mailbox",
            ));
        }
        let space = parse_space_ref(&format!("at:space/{account}/{kind}/{skey}"))
            .map_err(|e| err(400, "InvalidRequest", e))?;
        if !self
            .world
            .lock()
            .unwrap()
            .created_spaces
            .insert(space.to_string())
        {
            return Err(err(400, "SpaceAlreadyExists", space));
        }
        Ok(ok(json!({"space": space})))
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
            .contains(space.as_str())
        {
            return Err(err(410, "SpaceDeleted", space.as_str()));
        }
        if space.space_type().as_str() == MAILBOX
            && space.space_did().as_str() == account
            && space.skey().as_str() == "self"
        {
            return Ok(ok(json!({
                "space": space.as_str(),
                "policy": {"$type": "com.atproto.personalspace.policy"},
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
        let jti = format!("delegation-{}", world.next());
        // The Catbird authority checks the service-scoped audience before accepting a delegation.
        let token = delegation(
            &world.accounts[&account].key,
            &account,
            space.as_str(),
            &jti,
            now,
        );
        Ok(ok(json!({ "token": token })))
    }

    /// The personal-mailbox Space authority: only the owner's delegation earns a credential.
    fn space_credential(&self, body: &[u8], now: u64, key_field: &str) -> Reply {
        let body = parse(body)?;
        let space = space_uri(body["space"].as_str())?;
        let kid = text(&body, key_field)?;
        decode_p256_did_key(kid).map_err(|e| err(400, "InvalidRequest", e))?;
        if space.space_type().as_str() != MAILBOX
            || space.skey().as_str() != "self"
            || !self
                .world
                .lock()
                .unwrap()
                .accounts
                .contains_key(space.space_did().as_str())
        {
            return Err(err(
                404,
                "SpaceNotFound",
                "not a Space this PDS is authority of",
            ));
        }
        let delegation = complete(verify_delegation_token(
            text(&body, "delegationToken")?,
            space.space_did().as_str(),
            now as i64,
            &self.directory.resolver(space.space_did().as_str()),
        ))
        .map_err(|e| err(401, "InvalidDelegationToken", e))?;
        if delegation.iss != space.space_did().as_str() {
            return Err(err(
                403,
                "UserNotAuthorized",
                "only the owner reads a personal mailbox",
            ));
        }
        if delegation.sub != space.as_str() || delegation.exp <= now as i64 {
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
        let exp = now as i64 + 600;
        let jti = format!("credential-{}", world.next());
        let credential = mint_credential_token(
            &space_signer(&world.accounts[space.space_did().as_str()].key),
            space.space_did(),
            &space,
            kid,
            now as i64,
            exp,
            Some(&jti),
            Some("#atproto"),
        )
        .map_err(|e| err(500, "InternalServerError", e))?;
        let expires_at = chrono::DateTime::from_timestamp(exp, 0)
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
            .map(|((space, _), state)| {
                json!({
                    "space": space,
                    "repoRev": tid(state.rev_micros, 0),
                    "data": { "$bytes": STANDARD.encode(state.hash.digest()) },
                })
            })
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
        if staged.space.space_type().as_str() == CONVERSATION {
            self.notify_write(&staged).await?;
        }
        self.commit(staged)
    }

    fn stage_writes(&self, account: &str, body: &Value) -> Result<StagedWrite, Response> {
        let space = space_uri(body["space"].as_str())?;
        if text(body, "repo")? != account {
            return Err(err(403, "Forbidden", "repo must be the session account"));
        }
        match space.space_type().as_str() {
            CONVERSATION => {}
            MAILBOX if space.space_did().as_str() == account && space.skey().as_str() == "self" => {
            }
            _ => return Err(err(403, "Forbidden", "no write authority for this Space")),
        }
        let writes = body["writes"]
            .as_array()
            .ok_or_else(|| err(400, "InvalidRequest", "writes missing"))?;
        let world = self.world.lock().unwrap();
        if world.deleted_spaces.contains(space.as_str()) {
            return Err(err(410, "SpaceDeleted", space.as_str()));
        }
        let current = world
            .repos
            .get(&(space.to_string(), account.to_owned()))
            .cloned()
            .unwrap_or_default();
        let base_micros = current.rev_micros;
        // Strictly monotonic per repo, as the authority's notifyRepoUpdate requires.
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
            let uri = record_uri(&space, account, collection, &rkey)
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
                result["uri"] = uri.to_string().into();
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

    /// `com.atproto.space.notifyRepoUpdate` to the Space authority, service-authenticated
    /// by the writer; a refusal is the write's answer.
    async fn notify_write(&self, staged: &StagedWrite) -> Result<(), Response> {
        let endpoint = self
            .directory
            .parsed(staged.space.space_did().as_str())
            .and_then(|document| {
                document
                    .service("#atproto_mls", None)?
                    .service_endpoint
                    .clone()
            })
            .ok_or_else(|| err(502, "UpstreamFailure", "Space authority has no endpoint"))?;
        let token = {
            let world = self.world.lock().unwrap();
            mint_es256_service_jwt(
                &world.accounts[&staged.repo].key,
                &staged.repo,
                staged.space.space_did().as_str(),
                "com.atproto.space.notifyRepoUpdate",
            )
        };
        let response = self
            .http
            .post(format!(
                "{endpoint}/xrpc/com.atproto.space.notifyRepoUpdate"
            ))
            .bearer_auth(token)
            .json(&json!({
                "space": staged.space.as_str(),
                "repo": staged.repo,
                "repoRev": tid(staged.next.rev_micros, 0),
                "data": {"$bytes": STANDARD.encode(staged.next.hash.digest())},
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
        let key = (staged.space.to_string(), staged.repo.clone());
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
        let resolver = self.directory.resolver(space.space_did().as_str());
        let claims = complete(verify_credential_token(jwt, now as i64, &resolver))
            .map_err(|e| err(401, "InvalidSpaceCredential", e))?;
        if claims.iss != space.space_did().as_str()
            || claims.sub != space.as_str()
            || claims.exp <= now as i64
        {
            return Err(err(
                401,
                "InvalidSpaceCredential",
                "credential binding mismatch or expired",
            ));
        }
        complete(verify_credential_request(
            headers, writer, now as i64, &resolver,
        ))
        .map_err(|e| err(401, "BadSpaceSignature", e))?;
        let world = self.world.lock().unwrap();
        if world.revoked.contains_key(&claims.jti) {
            return Err(err(
                401,
                "CredentialRevoked",
                "credential revoked by the Space authority",
            ));
        }
        if world.deleted_spaces.contains(space.as_str()) {
            return Err(err(410, "SpaceDeleted", space.as_str()));
        }
        let Some(account) = world.accounts.get(writer) else {
            return Err(err(404, "RepoNotFound", writer));
        };
        if space.space_type().as_str() == MAILBOX
            && (writer != space.space_did().as_str() || space.skey().as_str() != "self")
        {
            return Err(err(
                403,
                "Forbidden",
                "a personal mailbox holds only its owner's repo",
            ));
        }
        let empty = Repo::default();
        let repo = world
            .repos
            .get(&(space.to_string(), writer.to_owned()))
            .unwrap_or(&empty);
        let want = header_value(headers, "accept-signature")?;
        let rev = tid(repo.rev_micros, 0);
        let data = repo.hash.digest();
        let commit = json!({"space": space.as_str(), "repo": writer, "ver": 1, "rev": rev, "data": {"$bytes": STANDARD.encode(data)}});
        match nsid {
            "com.atproto.space.getRecord" => {
                let collection = required(params, "collection")?;
                let rkey = required(params, "rkey")?;
                let record = repo
                    .records
                    .get(&(collection.to_owned(), rkey.to_owned()))
                    .ok_or_else(|| err(404, "RecordNotFound", rkey))?;
                let uri = record_uri(&space, writer, collection, rkey)
                    .map_err(|e| err(400, "InvalidRequest", e))?;
                let (secret, keyid) = shared_secret(&account.kem, want, MacProfile::Record)?;
                let cid = record
                    .cid
                    .parse()
                    .map_err(|e| err(500, "InternalServerError", e))?;
                let mac = sign_record_mac(&secret, &uri, &cid, &keyid)
                    .map_err(|e| err(500, "InternalServerError", e))?;
                Ok(with_mac(
                    ok(json!({"uri": uri, "cid": record.cid, "value": record.value})),
                    MacProfile::Record,
                    &mac,
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
                    .get(&(space.to_string(), writer.to_owned(), cid.to_owned()))
                    .ok_or_else(|| err(404, "BlobNotFound", cid))?;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(Body::from(bytes.clone()))
                    .unwrap())
            }
            _ => {
                // getRepo, getLatestCommit, listRepoOps: commit MACs.
                let (secret, keyid) = shared_secret(&account.kem, want, MacProfile::Commit)?;
                let writer = Did::parse(writer).map_err(|e| err(400, "InvalidRequest", e))?;
                let rev = rev
                    .parse()
                    .map_err(|e| err(500, "InternalServerError", e))?;
                let mac = sign_commit_mac(&secret, &space, &writer, &rev, &data, &keyid)
                    .map_err(|e| err(500, "InternalServerError", e))?;
                if nsid == "com.atproto.space.getRepo" {
                    let entries: Vec<_> = repo
                        .records
                        .iter()
                        .map(|((collection, rkey), record)| {
                            (format!("{collection}/{rkey}"), &record.typed)
                        })
                        .collect();
                    let entries: Vec<_> = entries
                        .iter()
                        .map(|(path, value)| (path.as_str(), *value))
                        .collect();
                    let body = write_star_repo(&space, &writer, &rev, &entries)
                        .map_err(|e| err(500, "InternalServerError", e))?;
                    let star = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.dasl.star")
                        .body(Body::from(body))
                        .unwrap();
                    return Ok(with_mac(star, MacProfile::Commit, &mac));
                }
                if nsid == "com.atproto.space.getLatestCommit" {
                    return Ok(with_mac(
                        ok(json!({ "commit": commit })),
                        MacProfile::Commit,
                        &mac,
                    ));
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
                Ok(with_mac(
                    ok(json!({ "ops": page, "commit": commit })),
                    MacProfile::Commit,
                    &mac,
                ))
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
            .and_then(|document| extract_signing_key(&document, "#atproto").ok())
            .ok_or_else(|| denied("authority has no #atproto key"))?;
        let alg = jwt_header["alg"].as_str().unwrap_or_default();
        if !key
            .verify(
                &decode(signature_b64)?,
                format!("{header_b64}.{claims_b64}").as_bytes(),
                alg,
            )
            .unwrap_or(false)
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
            space.space_did().as_str(),
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
            space.space_did().as_str(),
            "com.atproto.space.notifySpaceDeleted",
            now,
        )?;
        let mut world = self.world.lock().unwrap();
        world.repos.retain(|(s, _), _| s != space.as_str());
        world.space_blobs.retain(|(s, _, _), _| s != space.as_str());
        world.deleted_spaces.insert(space.into_string());
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
    let typed = verify_json_value_for_dag_cbor(value).map_err(|e| invalid(&e))?;
    if !matches!(typed, petrel_core::Value::Object(_)) {
        return Err(invalid(&"record root must be an object"));
    }
    let cid = compute_dagcbor_cid(&typed)
        .map_err(|e| invalid(&e))?
        .to_string();
    Ok(Record {
        value: value.clone(),
        cid,
        typed,
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
    let path = format!("{collection}/{rkey}");
    if add {
        hash.add_entry(&path, &record.cid);
    } else {
        hash.remove_entry(&path, &record.cid);
    }
}

fn shared_secret(
    kem: &SecretKey,
    want: Option<&str>,
    profile: MacProfile,
) -> Result<([u8; 32], String), Response> {
    let want = want.ok_or_else(|| err(400, "BadSpaceMac", "Accept-Signature required"))?;
    let request = parse_accept_signature(want).map_err(|e| err(400, "BadSpaceMac", e))?;
    if request.profile != profile {
        return Err(err(400, "BadSpaceMac", "unexpected MAC profile"));
    }
    let secret = decapsulate_p256(&kem.to_bytes().into(), &request.keyid)
        .map_err(|e| err(400, "BadSpaceMac", e))?;
    Ok((*secret, request.keyid))
}

fn record_uri(
    space: &SpaceRef,
    author: &str,
    collection: &str,
    key: &str,
) -> Result<AtUri, petrel_core::SyntaxError> {
    space.record_uri(&author.parse()?, &collection.parse()?, &key.parse()?)
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

fn space_uri(raw: Option<&str>) -> Result<SpaceRef, Response> {
    parse_space_ref(raw.ok_or_else(|| err(400, "InvalidRequest", "space required"))?)
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

fn with_mac(mut response: Response, profile: MacProfile, mac: &SpaceMacHeaders) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        (profile.response_header(), &mac.covered_signature),
        ("signature-input", &mac.signature_input),
        ("signature", &mac.signature),
    ] {
        headers.insert(
            name,
            HeaderValue::from_str(value).expect("Petrel generated valid header"),
        );
    }
    headers.insert(
        "access-control-expose-headers",
        HeaderValue::from_static(
            "Atproto-Space-Commit, Atproto-Space-Record, Signature-Input, Signature",
        ),
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
    _recovery_directory: tempfile::TempDir,
    child: Option<Child>,
}

impl CleanSlateDsProcess {
    pub async fn spawn(service_did: &str, s2s_secret: &[u8]) -> Result<Self> {
        let mut database_url = url::Url::parse(&pg_admin_url())?;
        let admin = pg_connect(database_url.as_str())
            .await
            .context("connect postgres admin db")?;
        let db_name = format!("clean_slate_fed_{}", Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE \"{db_name}\""))
            .await
            .with_context(|| format!("create database {db_name}"))?;
        database_url.set_path(&format!("/{db_name}"));
        let db_url = database_url.to_string();
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let receipt_key = SigningKey::random(&mut rand::rngs::OsRng);
        let recovery_directory = tempfile::tempdir()?;
        let kek_path = recovery_directory.path().join("kek");
        let mut key_file = tempfile::NamedTempFile::new_in(recovery_directory.path())?;
        key_file.write_all(&rand::random::<[u8; 32]>())?;
        key_file.persist(&kek_path)?;
        let mut child = Command::new(fixture_binary_path())
            .env("LABYRINTH_RECOVERY_SHARE_KEK_FILE", kek_path)
            .env("LABYRINTH_RECOVERY_SHARE_KEK_ID", &db_name)
            .env(
                "LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE",
                recovery_directory.path().join("deletions"),
            )
            .env("APP_ENV", "test")
            .env("TEST_DATABASE_URL", &db_url)
            .env("SERVICE_DID", service_did)
            .env("SIGNING_KEY_PEM", p256_to_pem(&signing_key))
            .env("RECEIPT_SIGNING_KEY_PEM", p256_to_pem(&receipt_key))
            .env(
                "RECEIPT_VERIFICATION_METHOD",
                format!("{service_did}#mls-receipt-1"),
            )
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
            _recovery_directory: recovery_directory,
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

/// The Space authority `ds` recorded, from the PDS's `notifyRepoUpdate`, exactly the
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

/// One HTTP exchange, including the XRPC error response when present.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub error: Option<String>,
    pub message: Option<String>,
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
    directory: DidDirectory,
    allowed_origins: Vec<String>,
    http: reqwest::Client,
    pub blocked_attempts: AtomicUsize,
    chat_bearer_token: Mutex<Option<String>>,
    account: Mutex<Option<AccountSession>>,
    exchanges: Mutex<Vec<Exchange>>,
}

impl ClientTransport {
    fn new(allowed_origins: Vec<String>, directory: DidDirectory) -> Self {
        Self {
            directory,
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
    fn execute_http(
        &self,
        mut request: PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        // Native clients resolve fixture DIDs at their independent identity authority.
        // Serve these registered documents in memory without contacting the public network.
        if request.method == "GET" {
            let did = request
                .url
                .strip_prefix("https://plc.directory/")
                .filter(|did| did.starts_with("did:plc:"))
                .map(str::to_owned)
                .or_else(|| {
                    request
                        .url
                        .strip_prefix("https://")?
                        .strip_suffix("/.well-known/did.json")
                        .map(|host| format!("did:web:{host}"))
                });
            if let Some(document) = did.and_then(|did| self.directory.document(&did)) {
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: vec![],
                    body: serde_json::to_vec(&document).expect("fixture DID document"),
                });
            }
        }
        // Advertised service endpoints use HTTPS. Map only a known local origin to
        // its corresponding loopback listener, then apply the same outbound check.
        for origin in &self.allowed_origins {
            let advertised = origin.replacen("http://", "https://", 1);
            if let Some(path) = request.url.strip_prefix(&format!("{advertised}/")) {
                request.url = format!("{origin}/{path}");
                break;
            }
        }
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
        let (status, error, message) = match &response {
            Ok(response) if !(200..300).contains(&response.status) => {
                let body = serde_json::from_slice::<Value>(&response.body).unwrap_or_default();
                (
                    response.status,
                    body["error"].as_str().map(str::to_owned),
                    body["message"].as_str().map(str::to_owned),
                )
            }
            Ok(response) => (response.status, None, None),
            Err(error) => (0, Some(error.to_string()), None),
        };
        self.exchanges.lock().unwrap().push(Exchange {
            method,
            url,
            status,
            error,
            message,
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
