//! https://tools.ietf.org/html/draft-ietf-mls-protocol-09#section-8
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

pub type Opaque = Vec<u8>; // TODO: delete

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("unsupported protocol version: {version}")]
    UnsupportedProtocolVersion { version: u8 },

    #[error("unknown extension type: {ty}")]
    UnknownExtensionType { ty: u16 },

    #[error("unknown ciphersuite: {suite}")]
    UnknownCipherSuite { suite: u16 },
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("I/O error")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct Opaque16(pub Vec<u8>);

impl Opaque16 {
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let size = reader.read_u16::<BigEndian>()? as usize;
        let mut buf = vec![0; size];
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodeError> {
        writer.write_u16::<BigEndian>(self.0.len() as u16)?;
        writer.write_all(&self.0)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolVersion {
    Mls10 = 1,
}

impl ProtocolVersion {
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        match reader.read_u8()? {
            1 => Ok(Self::Mls10),
            v => Err(DecodeError::UnsupportedProtocolVersion { version: v }),
        }
    }

    pub fn encode<W: Write>(self, writer: &mut W) -> Result<(), EncodeError> {
        writer.write_u8(self as u8)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExtensionType {
    Capabilities = 1,
    Lifetime = 2,
    KeyId = 3,
    ParentHash = 4,
    RatchetTree = 5,
}

impl ExtensionType {
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        match reader.read_u16::<BigEndian>()? {
            1 => Ok(Self::Capabilities),
            2 => Ok(Self::Lifetime),
            3 => Ok(Self::KeyId),
            4 => Ok(Self::ParentHash),
            5 => Ok(Self::RatchetTree),
            x => Err(DecodeError::UnknownExtensionType { ty: x }),
        }
    }

    pub fn encode<W: Write>(self, writer: &mut W) -> Result<(), EncodeError> {
        writer.write_u16::<BigEndian>(self as u16)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub extension_data: Opaque16,
}

impl Extension {
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        Ok(Self {
            extension_type: ExtensionType::decode(reader)?,
            extension_data: Opaque16::decode(reader)?,
        })
    }

    pub fn encode<W: Write>(&self, writer: &mut W) -> Result<(), EncodeError> {
        self.extension_type.encode(writer)?;
        self.extension_data.encode(writer)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CipherSuite {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 1,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 2,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 3,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 4,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 5,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 6,
}

impl CipherSuite {
    pub fn decode<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        match reader.read_u16::<BigEndian>()? {
            1 => Ok(Self::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            2 => Ok(Self::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256),
            3 => Ok(Self::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            4 => Ok(Self::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            5 => Ok(Self::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521),
            6 => Ok(Self::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            x => Err(DecodeError::UnknownCipherSuite { suite: x }),
        }
    }

    pub fn encode<W: Write>(self, writer: &mut W) -> Result<(), EncodeError> {
        writer.write_u16::<BigEndian>(self as u16)?;
        Ok(())
    }
}

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
