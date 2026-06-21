#![no_std]

// The service-side modules require std and are only available on non-WASM targets.
#[cfg(not(target_arch = "wasm32"))]
#[macro_use]
extern crate std;

#[cfg(not(target_arch = "wasm32"))]
pub mod cache;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod event;
#[cfg(not(target_arch = "wasm32"))]
pub mod hash_validator;
#[cfg(not(target_arch = "wasm32"))]
pub mod metrics;
#[cfg(not(target_arch = "wasm32"))]
pub mod rate_limit;
#[cfg(not(target_arch = "wasm32"))]
pub mod stellar;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, BytesN, Env, Vec,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DocumentStatus {
    Active,
    Revoked,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentRecord {
    pub issuer: Address,
    pub owner: Address,
    pub timestamp: u64,
    pub status: DocumentStatus,
}

#[contracttype]
pub enum DataKey {
    Document(BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DocumentInfo {
    pub owner: Address,
    pub document_hash: BytesN<32>,
}

pub const MAX_BATCH_SIZE: u32 = 20;

/// Enumeration of all error conditions that can occur within the ProofStell contract.
///
/// Each variant maps to a unique numeric code for Soroban client interoperability,
/// allowing callers to distinguish failure cases and implement appropriate recovery logic.
///
/// # Error Codes
/// | Variant                | Code | Description                                              |
/// |------------------------|------|----------------------------------------------------------|
/// | `DocumentNotFound`     | 1    | No record exists for the given document hash             |
/// | `AlreadyRegistered`    | 2    | A document with this hash has already been registered    |
/// | `OnlyIssuerCanRevoke`  | 3    | The caller is not the original issuer of the document    |
/// | `AlreadyRevoked`       | 4    | The document has already been revoked                    |
/// | `InvalidOwner`         | 5    | The provided owner address is not valid for this op      |
/// | `InvalidIssuer`        | 6    | The provided issuer address is not valid for this op     |
/// | `BatchTooLarge`        | 7    | Batch exceeds the 20-document limit                      |
/// | `BatchEmpty`           | 8    | Batch input is empty                                     |
#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// No record exists for the provided document hash. Code: 1
    DocumentNotFound = 1,
    /// A document with this hash is already registered. Code: 2
    AlreadyRegistered = 2,
    /// The caller is not the original issuer and cannot perform this action. Code: 3
    OnlyIssuerCanRevoke = 3,
    /// The document has already been revoked and cannot be revoked again. Code: 4
    AlreadyRevoked = 4,
    /// The provided owner address failed validation. Code: 5
    InvalidOwner = 5,
    /// The provided issuer address failed validation. Code: 6
    InvalidIssuer = 6,
    /// The batch exceeds the maximum allowed size (20). Code: 7
    BatchTooLarge = 7,
    /// The batch is empty. Code: 8
    BatchEmpty = 8,
}

#[contractevent(topics = ["register"], data_format = "vec")]
pub struct DocumentRegistered {
    #[topic]
    pub issuer: Address,
    pub owner: Address,
    pub document_hash: BytesN<32>,
}

#[contractevent(topics = ["revoke"], data_format = "vec")]
pub struct DocumentRevoked {
    #[topic]
    pub issuer: Address,
    pub document_hash: BytesN<32>,
}

#[contract]
pub struct ProofStellContract;

#[contractimpl]
impl ProofStellContract {
    /// Registers a new document on-chain, associating it with an issuer and owner.
    ///
    /// The issuer must authorize this call. Each document hash can only be registered once.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `issuer`        - Address of the entity registering the document (must authorize)
    /// * `owner`         - Address of the document's owner
    /// * `document_hash` - 32-byte unique hash identifying the document
    ///
    /// # Returns
    /// The newly created [`DocumentRecord`] with `DocumentStatus::Active`
    ///
    /// # Errors
    /// * [`ContractError::AlreadyRegistered`] — if a record already exists for this hash
    pub fn register_document(
        env: Env,
        issuer: Address,
        owner: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentRecord, ContractError> {
        issuer.require_auth();

        let key = DataKey::Document(document_hash.clone());

        if env.storage().persistent().has(&key) {
            return Err(ContractError::AlreadyRegistered);
        }

        let record = DocumentRecord {
            issuer: issuer.clone(),
            owner,
            timestamp: env.ledger().timestamp(),
            status: DocumentStatus::Active,
        };

        env.storage().persistent().set(&key, &record);
        DocumentRegistered {
            issuer,
            owner: record.owner.clone(),
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    /// Retrieves a document record by its hash from persistent storage.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `Some(DocumentRecord)` if found, `None` otherwise
    pub fn get_document(env: Env, document_hash: BytesN<32>) -> Option<DocumentRecord> {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().get(&key)
    }

    /// Checks whether a document exists and is currently active.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `true` only if the document exists and has `DocumentStatus::Active`
    pub fn verify_document(env: Env, document_hash: BytesN<32>) -> bool {
        let key = DataKey::Document(document_hash);
        env.storage()
            .persistent()
            .get::<DataKey, DocumentRecord>(&key)
            .map_or(false, |record| record.status == DocumentStatus::Active)
    }

    /// Returns the status of a document, or an error if it does not exist.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Errors
    /// * [`ContractError::DocumentNotFound`] — if no record exists for the given hash
    pub fn get_document_status(
        env: Env,
        document_hash: BytesN<32>,
    ) -> Result<DocumentStatus, ContractError> {
        let key = DataKey::Document(document_hash);
        env.storage()
            .persistent()
            .get::<DataKey, DocumentRecord>(&key)
            .map(|record| record.status)
            .ok_or(ContractError::DocumentNotFound)
    }

    /// Checks whether a document exists in storage, regardless of its status.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `document_hash` - 32-byte hash identifying the document
    ///
    /// # Returns
    /// `true` if any record (active or revoked) is stored under this hash
    pub fn document_exists(env: Env, document_hash: BytesN<32>) -> bool {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().has(&key)
    }

    /// Revokes a previously registered document, preventing future verification.
    ///
    /// Only the original issuer of the document may revoke it. A document that has
    /// already been revoked cannot be revoked again.
    ///
    /// # Arguments
    /// * `env`           - The Soroban environment
    /// * `issuer`        - Address of the original issuer (must authorize)
    /// * `document_hash` - 32-byte hash identifying the document to revoke
    ///
    /// # Returns
    /// The updated [`DocumentRecord`] with `DocumentStatus::Revoked`
    ///
    /// # Errors
    /// * [`ContractError::DocumentNotFound`]    — if no record exists for this hash
    /// * [`ContractError::OnlyIssuerCanRevoke`] — if the caller is not the original issuer
    /// * [`ContractError::AlreadyRevoked`]      — if the document is already revoked
    pub fn revoke_document(
        env: Env,
        issuer: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentRecord, ContractError> {
        issuer.require_auth();

        let key = DataKey::Document(document_hash.clone());

        let mut record: DocumentRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ContractError::DocumentNotFound)?;

        if record.issuer != issuer {
            return Err(ContractError::OnlyIssuerCanRevoke);
        }

        if record.status == DocumentStatus::Revoked {
            return Err(ContractError::AlreadyRevoked);
        }

        record.status = DocumentStatus::Revoked;

        env.storage().persistent().set(&key, &record);
        DocumentRevoked {
            issuer,
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    /// Registers multiple documents in a single atomic transaction.
    ///
    /// The issuer authorizes once for the entire batch. All documents must be
    /// valid or the entire batch fails — no partial state is written.
    ///
    /// # Arguments
    /// * `env`       - The Soroban environment
    /// * `issuer`    - Address of the entity registering the documents (must authorize)
    /// * `documents` - Vector of [`DocumentInfo`] (owner + hash pairs), max 20 items
    ///
    /// # Returns
    /// A vector of newly created [`DocumentRecord`]s, all with `DocumentStatus::Active`
    ///
    /// # Errors
    /// * [`ContractError::BatchEmpty`]       — if the vector is empty
    /// * [`ContractError::BatchTooLarge`]    — if the vector exceeds 20 items
    /// * [`ContractError::AlreadyRegistered`] — if any document hash is already registered
    pub fn batch_register_documents(
        env: Env,
        issuer: Address,
        documents: Vec<DocumentInfo>,
    ) -> Result<Vec<DocumentRecord>, ContractError> {
        issuer.require_auth();

        if documents.is_empty() {
            return Err(ContractError::BatchEmpty);
        }
        if documents.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }

        let mut records = Vec::new(&env);

        for doc in documents.iter() {
            let key = DataKey::Document(doc.document_hash.clone());

            if env.storage().persistent().has(&key) {
                return Err(ContractError::AlreadyRegistered);
            }

            let record = DocumentRecord {
                issuer: issuer.clone(),
                owner: doc.owner.clone(),
                timestamp: env.ledger().timestamp(),
                status: DocumentStatus::Active,
            };

            env.storage().persistent().set(&key, &record);
            DocumentRegistered {
                issuer: issuer.clone(),
                owner: doc.owner.clone(),
                document_hash: doc.document_hash.clone(),
            }
            .publish(&env);

            records.push_back(record);
        }

        Ok(records)
    }

    /// Revokes multiple documents in a single atomic transaction.
    ///
    /// The issuer authorizes once for the entire batch. All documents must be
    /// revocable or the entire batch fails — no partial state is written.
    ///
    /// # Arguments
    /// * `env`            - The Soroban environment
    /// * `issuer`         - Address of the original issuer (must authorize)
    /// * `document_hashes` - Vector of 32-byte document hashes to revoke, max 20 items
    ///
    /// # Returns
    /// A vector of updated [`DocumentRecord`]s, all with `DocumentStatus::Revoked`
    ///
    /// # Errors
    /// * [`ContractError::BatchEmpty`]          — if the vector is empty
    /// * [`ContractError::BatchTooLarge`]       — if the vector exceeds 20 items
    /// * [`ContractError::DocumentNotFound`]    — if any hash has no record
    /// * [`ContractError::OnlyIssuerCanRevoke`] — if the caller is not the original issuer of any document
    /// * [`ContractError::AlreadyRevoked`]      — if any document is already revoked
    pub fn batch_revoke_documents(
        env: Env,
        issuer: Address,
        document_hashes: Vec<BytesN<32>>,
    ) -> Result<Vec<DocumentRecord>, ContractError> {
        issuer.require_auth();

        if document_hashes.is_empty() {
            return Err(ContractError::BatchEmpty);
        }
        if document_hashes.len() > MAX_BATCH_SIZE {
            return Err(ContractError::BatchTooLarge);
        }

        let mut records = Vec::new(&env);

        for document_hash in document_hashes.iter() {
            let key = DataKey::Document(document_hash.clone());

            let mut record: DocumentRecord = env
                .storage()
                .persistent()
                .get(&key)
                .ok_or(ContractError::DocumentNotFound)?;

            if record.issuer != issuer {
                return Err(ContractError::OnlyIssuerCanRevoke);
            }

            if record.status == DocumentStatus::Revoked {
                return Err(ContractError::AlreadyRevoked);
            }

            record.status = DocumentStatus::Revoked;
            env.storage().persistent().set(&key, &record);
            DocumentRevoked {
                issuer: issuer.clone(),
                document_hash: document_hash.clone(),
            }
            .publish(&env);

            records.push_back(record);
        }

        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        ProofStellContractClient<'static>,
        Address,
        Address,
        BytesN<32>,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let contract_id = env.register(ProofStellContract, ());
        let client = ProofStellContractClient::new(&env, &contract_id);
        let issuer = Address::generate(&env);
        let owner = Address::generate(&env);
        let document_hash = BytesN::from_array(&env, &[7; 32]);

        (env, client, issuer, owner, document_hash)
    }

    #[test]
    fn registers_and_verifies_document() {
        let (_env, client, issuer, owner, document_hash) = setup();

        let record = client.register_document(&issuer, &owner, &document_hash);

        assert_eq!(record.issuer, issuer);
        assert_eq!(record.owner, owner);
        assert_eq!(record.status, DocumentStatus::Active);
        assert!(client.verify_document(&document_hash));
    }

    #[test]
    fn returns_document_record() {
        let (_env, client, issuer, owner, document_hash) = setup();

        let record = client.register_document(&issuer, &owner, &document_hash);

        assert_eq!(client.get_document(&document_hash), Some(record));
    }

    #[test]
    fn revokes_document() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let record = client.revoke_document(&issuer, &document_hash);

        assert_eq!(record.status, DocumentStatus::Revoked);
        assert!(!client.verify_document(&document_hash));
    }

    #[test]
    fn prevents_duplicate_registration() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let err = client
            .try_register_document(&issuer, &owner, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRegistered);
    }

    #[test]
    fn prevents_non_issuer_revocation() {
        let (env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let other = Address::generate(&env);
        let err = client
            .try_revoke_document(&other, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::OnlyIssuerCanRevoke);
    }

    #[test]
    fn prevents_double_revocation() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRevoked);
    }

    #[test]
    fn revoke_nonexistent_document_returns_not_found() {
        let (_env, client, issuer, _owner, document_hash) = setup();

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
    }

    #[test]
    fn get_document_status_returns_not_found_for_missing_document() {
        let (_env, client, _issuer, _owner, document_hash) = setup();

        let err = client
            .try_get_document_status(&document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
    }

    #[test]
    fn get_document_status_returns_active_after_register() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let status = client.get_document_status(&document_hash);

        assert_eq!(status, DocumentStatus::Active);
    }

    #[test]
    fn get_document_status_returns_revoked_after_revoke() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);
        let status = client.get_document_status(&document_hash);

        assert_eq!(status, DocumentStatus::Revoked);
    }

    #[test]
    fn document_exists_returns_false_before_registration() {
        let (_env, client, _issuer, _owner, document_hash) = setup();

        assert!(!client.document_exists(&document_hash));
    }

    #[test]
    fn document_exists_returns_true_after_registration() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        assert!(client.document_exists(&document_hash));
    }

    // --- batch_register_documents ---

    #[test]
    fn batch_register_all_succeed() {
        let (env, client, issuer, owner, _) = setup();

        let docs = soroban_sdk::vec![
            &env,
            DocumentInfo { owner: owner.clone(), document_hash: BytesN::from_array(&env, &[1; 32]) },
            DocumentInfo { owner: owner.clone(), document_hash: BytesN::from_array(&env, &[2; 32]) },
            DocumentInfo { owner: owner.clone(), document_hash: BytesN::from_array(&env, &[3; 32]) },
        ];

        let records = client.batch_register_documents(&issuer, &docs);

        assert_eq!(records.len(), 3);
        for record in records.iter() {
            assert_eq!(record.status, DocumentStatus::Active);
            assert_eq!(record.issuer, issuer);
        }
    }

    #[test]
    fn batch_register_fails_on_duplicate() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let docs = soroban_sdk::vec![
            &env,
            DocumentInfo { owner: owner.clone(), document_hash: BytesN::from_array(&env, &[3; 32]) },
            DocumentInfo { owner: owner.clone(), document_hash: hash1.clone() },
            DocumentInfo { owner: owner.clone(), document_hash: hash2.clone() },
        ];

        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRegistered);
        // hash2 must not have been stored (batch was atomic)
        assert!(!client.document_exists(&hash2));
    }

    #[test]
    fn batch_register_rejects_empty() {
        let (env, client, issuer, _, _) = setup();

        let docs: soroban_sdk::Vec<DocumentInfo> = soroban_sdk::vec![&env];
        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchEmpty);
    }

    #[test]
    fn batch_register_rejects_oversized() {
        let (env, client, issuer, owner, _) = setup();

        let mut docs = soroban_sdk::vec![&env];
        for i in 0..21u8 {
            docs.push_back(DocumentInfo {
                owner: owner.clone(),
                document_hash: BytesN::from_array(&env, &[i; 32]),
            });
        }

        let err = client
            .try_batch_register_documents(&issuer, &docs)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchTooLarge);
    }

    // --- batch_revoke_documents ---

    #[test]
    fn batch_revoke_all_succeed() {
        let (env, client, issuer, owner, _) = setup();

        let hashes = [
            BytesN::from_array(&env, &[1; 32]),
            BytesN::from_array(&env, &[2; 32]),
            BytesN::from_array(&env, &[3; 32]),
        ];
        for h in &hashes {
            client.register_document(&issuer, &owner, h);
        }

        let hash_vec = soroban_sdk::vec![&env, hashes[0].clone(), hashes[1].clone(), hashes[2].clone()];
        let records = client.batch_revoke_documents(&issuer, &hash_vec);

        assert_eq!(records.len(), 3);
        for record in records.iter() {
            assert_eq!(record.status, DocumentStatus::Revoked);
        }
    }

    #[test]
    fn batch_revoke_fails_on_missing() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash_missing = BytesN::from_array(&env, &[99; 32]);
        client.register_document(&issuer, &owner, &hash1);

        let hash_vec = soroban_sdk::vec![&env, hash1.clone(), hash_missing];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
        // hash1 must still be Active (batch was atomic)
        assert_eq!(client.get_document_status(&hash1), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_fails_on_wrong_issuer() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);
        client.register_document(&issuer, &owner, &hash2);

        let other = Address::generate(&env);
        let hash_vec = soroban_sdk::vec![&env, hash1.clone(), hash2.clone()];
        let err = client
            .try_batch_revoke_documents(&other, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::OnlyIssuerCanRevoke);
        assert_eq!(client.get_document_status(&hash1), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_fails_on_already_revoked() {
        let (env, client, issuer, owner, _) = setup();

        let hash1 = BytesN::from_array(&env, &[1; 32]);
        let hash2 = BytesN::from_array(&env, &[2; 32]);
        client.register_document(&issuer, &owner, &hash1);
        client.register_document(&issuer, &owner, &hash2);
        client.revoke_document(&issuer, &hash1);

        let hash_vec = soroban_sdk::vec![&env, hash1, hash2.clone()];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRevoked);
        assert_eq!(client.get_document_status(&hash2), DocumentStatus::Active);
    }

    #[test]
    fn batch_revoke_rejects_empty() {
        let (_env, client, issuer, _, _) = setup();

        let hash_vec: soroban_sdk::Vec<BytesN<32>> = soroban_sdk::vec![&_env];
        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchEmpty);
    }

    #[test]
    fn batch_revoke_rejects_oversized() {
        let (env, client, issuer, owner, _) = setup();

        let mut hash_vec: soroban_sdk::Vec<BytesN<32>> = soroban_sdk::vec![&env];
        for i in 0..21u8 {
            let h = BytesN::from_array(&env, &[i; 32]);
            client.register_document(&issuer, &owner, &h);
            hash_vec.push_back(h);
        }

        let err = client
            .try_batch_revoke_documents(&issuer, &hash_vec)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::BatchTooLarge);
    }
}
