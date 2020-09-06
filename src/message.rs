//! https://tools.ietf.org/html/draft-ietf-mls-protocol-09#section-8

pub type Opaque = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    Mls10 = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtensionType {
    Invalid = 0,
    SupportedVersions = 1,
    SupportedCiphersuites = 2,
    Expiration = 3,
    KeyId = 4,
    ParentHash = 5,
    // 2^16-1
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Opaque, // 0..2^16-1
}

pub type CipherSuite = [u8; 2];

pub type HpkePublicKey = Opaque; // 0..2^16-1

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CredentialType {
    Basic = 0,
    X509 = 1,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Credential {
    Basic(BasicCredential),
    X509 {
        cert_data: Opaque, // 1..2^24-1
    },
}

#[derive(Debug, Clone)]
pub struct BasicCredential {
    pub identity: Opaque, // 0..2^16-1
    pub algorithm: SignatureScheme,
    pub public_key: SignaturePublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureScheme {
    EcdsaSecp256r1Sha256 = 0x0403,
    Ed25519 = 0x0807,
    // 0xFFFF
}

pub type SignaturePublicKey = Opaque; // 1..2^16-1

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContentType {
    Invalid = 0,
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SenderType {
    Invalid = 0,
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sender {
    pub sender_type: SenderType,
    pub sender: u32,
}

#[derive(Debug, Clone)]
pub struct MlsPlaintext {
    pub group_id: Opaque, // 0..255
    pub epoch: u64,
    pub sender: Sender,
    pub authenticated_data: Opaque, // 0..2^32-1
    pub content: Content,
    pub signature: Opaque, // 0..2^16-1
}

#[derive(Debug, Clone)]
pub struct MlsCiphertext {
    pub group_id: Opaque, // 0..255
    pub epoch: u64,
    pub content: Content,
    pub authenticated_data: Opaque,    // 0..2^32-1
    pub sender_data_nonce: Opaque,     // 0..255
    pub encrypted_sender_data: Opaque, // 0..255
    pub ciphertext: Opaque,            // 0..2^32-1
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Content {
    Application {
        application_data: Opaque, // 0..2^32-1
    },
    Proposal {
        proposal: Proposal,
    },
    Commit {
        commit: Commit,
        confirmation: Opaque, // 0..255
    },
}

impl Content {
    pub fn content_type(&self) -> ContentType {
        match self {
            Self::Application { .. } => ContentType::Application,
            Self::Proposal { .. } => ContentType::Proposal,
            Self::Commit { .. } => ContentType::Commit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProposalType {
    Invalid = 0,
    Add = 1,
    Update = 2,
    Remove = 3,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Proposal {
    Add(Add),
    Update(Update),
    Remove(Remove),
}

impl Proposal {
    pub fn proposal_type(&self) -> ProposalType {
        match self {
            Self::Add(_) => ProposalType::Add,
            Self::Update(_) => ProposalType::Update,
            Self::Remove(_) => ProposalType::Remove,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Add {
    pub key_package: KeyPackage,
}

#[derive(Debug, Clone)]
pub struct Update {
    pub key_package: KeyPackage,
}

#[derive(Debug, Clone)]
pub struct Remove {
    pub removed: u32,
}

#[derive(Debug, Clone)]
pub struct KeyPackage {
    pub version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: HpkePublicKey,
    pub extensions: Vec<Extension>, // 0..2^16-1
    pub signature: Opaque,          // 0..2^16-1
}

pub type ProposalId = Opaque; // 0..255

#[derive(Debug, Clone)]
pub struct Commit {
    pub updates: Vec<ProposalId>, // 0..2^16-1
    pub removes: Vec<ProposalId>, // 0..2^16-1
    pub adds: Vec<ProposalId>,    // 0..2^16-1
    pub key_package: KeyPackage,
    pub path: DirectPath,
}

#[derive(Debug, Clone)]
pub struct DirectPath {
    pub nodes: DirectPathNode, // 0..2^16-1
}

#[derive(Debug, Clone)]
pub struct DirectPathNode {
    pub public_key: HpkePublicKey,
    pub encrypted_path_secret: Vec<HpkeCiphertext>, // 0..2^16-1
}

#[derive(Debug, Clone)]
pub struct HpkeCiphertext {
    pub kem_output: Opaque, // 0..2^16-1
    pub ciphertext: Opaque, // 0..2^16-1
}
