#![no_std]

extern crate alloc;

use soroban_sdk::{contract, contracterror, contractevent, contractimpl, contracttype, vec, Address, BytesN, Env, Symbol};

#[cfg(not(target_arch = "wasm32"))]
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

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
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
    EventCount(BytesN<32>),
    Event(BytesN<32>, u64),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum EventType {
    DocumentRegistered,
    DocumentRevoked,
    DocumentVerified,
    DocumentAuthorizationFailed,
    DocumentOwnerChanged,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, Copy)]
pub enum AuthFailureReason {
    DocumentNotFound,
    NotIssuer,
    AlreadyRevoked,
    NotOwner,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractEventRecord {
    pub sequence: u64,
    pub timestamp: u64,
    pub actor: Address,
    pub event_type: EventType,
    pub auth_failure_reason: u32,
}

#[contracterror]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    DocumentNotFound = 1,
    AlreadyRegistered = 2,
    OnlyIssuerCanRevoke = 3,
    AlreadyRevoked = 4,
    InvalidOwner = 5,
    InvalidIssuer = 6,
}

const NONE_REASON: u32 = u32::MAX;

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

#[contractevent(topics = ["verify"], data_format = "vec")]
pub struct DocumentVerified {
    #[topic]
    pub actor: Address,
    pub document_hash: BytesN<32>,
    pub status: DocumentStatus,
}

#[contractevent(topics = ["auth_failed"], data_format = "vec")]
pub struct DocumentAuthorizationFailed {
    #[topic]
    pub actor: Address,
    pub document_hash: BytesN<32>,
    pub reason: AuthFailureReason,
}

#[contractevent(topics = ["owner_changed"], data_format = "vec")]
pub struct DocumentOwnerChanged {
    #[topic]
    pub actor: Address,
    pub document_hash: BytesN<32>,
    pub previous_owner: Address,
    pub new_owner: Address,
}

#[contract]
pub struct ProofStellContract;

#[contractimpl]
impl ProofStellContract {
    fn emit_event(
        env: &Env,
        document_hash: &BytesN<32>,
        actor: &Address,
        event_type: EventType,
        auth_failure_reason: Option<AuthFailureReason>,
    ) {
        let count_key = DataKey::EventCount(document_hash.clone());
        let next_sequence: u64 = env.storage().persistent().get(&count_key).unwrap_or(0) + 1;
        env.storage().persistent().set(&count_key, &next_sequence);

        let event_key = DataKey::Event(document_hash.clone(), next_sequence);
        let timestamp = env.ledger().timestamp();

        let record = ContractEventRecord {
            sequence: next_sequence,
            timestamp,
            actor: actor.clone(),
            event_type,
            auth_failure_reason: auth_failure_reason.map(|r| r as u32).unwrap_or(NONE_REASON),
        };

        env.storage().persistent().set(&event_key, &record);
    }

    pub fn get_document_event_count(env: Env, document_hash: BytesN<32>) -> u64 {
        let count_key = DataKey::EventCount(document_hash);
        env.storage().persistent().get(&count_key).unwrap_or(0)
    }

    pub fn get_document_event(env: Env, document_hash: BytesN<32>, index: u64) -> Option<ContractEventRecord> {
        let event_key = DataKey::Event(document_hash, index);
        env.storage().persistent().get(&event_key)
    }

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

        Self::emit_event(
            &env,
            &document_hash,
            &issuer,
            EventType::DocumentRegistered,
            None,
        );

        DocumentRegistered {
            issuer,
            owner: record.owner.clone(),
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    pub fn get_document(env: Env, document_hash: BytesN<32>) -> Option<DocumentRecord> {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().get(&key)
    }

    pub fn verify_document(
        env: Env,
        caller: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentStatus, ContractError> {
        let key = DataKey::Document(document_hash.clone());
        let record: DocumentRecord = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => {
                let reason = AuthFailureReason::DocumentNotFound;
                Self::emit_event(
                    &env,
                    &document_hash,
                    &caller,
                    EventType::DocumentAuthorizationFailed,
                    Some(reason),
                );
                DocumentAuthorizationFailed {
                    actor: caller,
                    document_hash,
                    reason,
                }
                .publish(&env);
                return Err(ContractError::DocumentNotFound);
            }
        };

        let status = record.status;

        Self::emit_event(
            &env,
            &document_hash,
            &caller,
            EventType::DocumentVerified,
            None,
        );

        DocumentVerified {
            actor: caller,
            document_hash,
            status,
        }
        .publish(&env);

        Ok(status)
    }

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

    pub fn document_exists(env: Env, document_hash: BytesN<32>) -> bool {
        let key = DataKey::Document(document_hash);
        env.storage().persistent().has(&key)
    }

    pub fn revoke_document(
        env: Env,
        issuer: Address,
        document_hash: BytesN<32>,
    ) -> Result<DocumentRecord, ContractError> {
        issuer.require_auth();

        let key = DataKey::Document(document_hash.clone());

        let mut record: DocumentRecord = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => {
                let reason = AuthFailureReason::DocumentNotFound;
                Self::emit_event(
                    &env,
                    &document_hash,
                    &issuer,
                    EventType::DocumentAuthorizationFailed,
                    Some(reason),
                );
                DocumentAuthorizationFailed {
                    actor: issuer,
                    document_hash,
                    reason,
                }
                .publish(&env);
                return Err(ContractError::DocumentNotFound);
            }
        };

        if record.issuer != issuer {
            let reason = AuthFailureReason::NotIssuer;
            Self::emit_event(
                &env,
                &document_hash,
                &issuer,
                EventType::DocumentAuthorizationFailed,
                Some(reason),
            );
            DocumentAuthorizationFailed {
                actor: issuer,
                document_hash,
                reason,
            }
            .publish(&env);
            return Err(ContractError::OnlyIssuerCanRevoke);
        }

        if record.status == DocumentStatus::Revoked {
            let reason = AuthFailureReason::AlreadyRevoked;
            Self::emit_event(
                &env,
                &document_hash,
                &issuer,
                EventType::DocumentAuthorizationFailed,
                Some(reason),
            );
            DocumentAuthorizationFailed {
                actor: issuer,
                document_hash,
                reason,
            }
            .publish(&env);
            return Err(ContractError::AlreadyRevoked);
        }

        record.status = DocumentStatus::Revoked;

        env.storage().persistent().set(&key, &record);

        Self::emit_event(
            &env,
            &document_hash,
            &issuer,
            EventType::DocumentRevoked,
            None,
        );

        DocumentRevoked {
            issuer,
            document_hash,
        }
        .publish(&env);

        Ok(record)
    }

    pub fn change_owner(
        env: Env,
        current_owner: Address,
        document_hash: BytesN<32>,
        new_owner: Address,
    ) -> Result<DocumentRecord, ContractError> {
        current_owner.require_auth();

        let key = DataKey::Document(document_hash.clone());

        let mut record: DocumentRecord = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => {
                let reason = AuthFailureReason::DocumentNotFound;
                Self::emit_event(
                    &env,
                    &document_hash,
                    &current_owner,
                    EventType::DocumentAuthorizationFailed,
                    Some(reason),
                );
                DocumentAuthorizationFailed {
                    actor: current_owner,
                    document_hash,
                    reason,
                }
                .publish(&env);
                return Err(ContractError::DocumentNotFound);
            }
        };

        if record.owner != current_owner {
            let reason = AuthFailureReason::NotOwner;
            Self::emit_event(
                &env,
                &document_hash,
                &current_owner,
                EventType::DocumentAuthorizationFailed,
                Some(reason),
            );
            DocumentAuthorizationFailed {
                actor: current_owner,
                document_hash,
                reason,
            }
            .publish(&env);
            return Err(ContractError::InvalidOwner);
        }

        let previous_owner = record.owner.clone();
        record.owner = new_owner.clone();

        env.storage().persistent().set(&key, &record);

        Self::emit_event(
            &env,
            &document_hash,
            &current_owner,
            EventType::DocumentOwnerChanged,
            None,
        );

        DocumentOwnerChanged {
            actor: current_owner,
            document_hash,
            previous_owner,
            new_owner,
        }
        .publish(&env);

        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, ProofStellContractClient<'static>, Address, Address, BytesN<32>) {
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
        let status = client.verify_document(&issuer, &document_hash);
        assert!(status.is_ok());
        assert_eq!(status.unwrap(), DocumentStatus::Active);
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
        let status = client.verify_document(&issuer, &document_hash);
        assert_eq!(status.unwrap(), DocumentStatus::Revoked);
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

    #[test]
    fn event_emission_records_document_registered() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let count = client.get_document_event_count(&document_hash);
        assert_eq!(count, 1);
        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert!(matches!(
            event.event_type,
            EventType::DocumentRegistered
        ));
        assert_eq!(event.actor, issuer);
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn event_emission_records_document_revoked() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);

        let count = client.get_document_event_count(&document_hash);
        assert_eq!(count, 2);
        let event = client.get_document_event(&document_hash, 2).unwrap();
        assert!(matches!(
            event.event_type,
            EventType::DocumentRevoked
        ));
        assert_eq!(event.actor, issuer);
        assert_eq!(event.sequence, 2);
    }

    #[test]
    fn event_emission_records_document_verified() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let status = client.verify_document(&issuer, &document_hash);

        assert_eq!(status.unwrap(), DocumentStatus::Active);
        let event = client.get_document_event(&document_hash, 2).unwrap();
        assert!(matches!(
            event.event_type,
            EventType::DocumentVerified
        ));
        assert_eq!(event.actor, issuer);
    }

    #[test]
    fn event_emission_records_document_verified_for_revoked_document() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);
        let status = client.verify_document(&issuer, &document_hash);

        assert_eq!(status.unwrap(), DocumentStatus::Revoked);
        let count = client.get_document_event_count(&document_hash);
        assert!(count >= 2);
    }

    #[test]
    fn event_emission_records_auth_failure_for_missing_document() {
        let (_env, client, issuer, _owner, document_hash) = setup();

        let err = client
            .try_verify_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
        let count = client.get_document_event_count(&document_hash);
        assert_eq!(count, 1);
        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert!(matches!(
            event.event_type,
            EventType::DocumentAuthorizationFailed
        ));
        assert_eq!(event.auth_failure_reason, AuthFailureReason::DocumentNotFound as u32);
    }

    #[test]
    fn event_emission_records_auth_failure_for_missing_document_on_revoke() {
        let (_env, client, issuer, _owner, document_hash) = setup();

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
        let count = client.get_document_event_count(&document_hash);
        assert_eq!(count, 1);
        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert!(matches!(event.event_type, EventType::DocumentAuthorizationFailed));
        assert_eq!(event.auth_failure_reason, AuthFailureReason::DocumentNotFound as u32);
    }

    #[test]
    fn event_emission_records_auth_failure_for_non_issuer_revoke() {
        let (env, client, _issuer, owner, document_hash) = setup();

        let other = Address::generate(&env);
        client.register_document(&other, &owner, &document_hash);
        client.revoke_document(&other, &document_hash);

        let err = client
            .try_revoke_document(&owner, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::OnlyIssuerCanRevoke);
        let count = client.get_document_event_count(&document_hash);
        assert!(count >= 2);
    }

    #[test]
    fn event_emission_records_auth_failure_for_already_revoked() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.revoke_document(&issuer, &document_hash);

        let err = client
            .try_revoke_document(&issuer, &document_hash)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::AlreadyRevoked);
        let count = client.get_document_event_count(&document_hash);
        assert!(count >= 2);
    }

    #[test]
    fn event_emission_records_auth_failure_for_missing_document_on_change_owner() {
        let (_env, client, issuer, owner, document_hash) = setup();

        let err = client
            .try_change_owner(&owner, &document_hash, &owner)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::DocumentNotFound);
        let count = client.get_document_event_count(&document_hash);
        assert_eq!(count, 1);
        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert!(matches!(event.event_type, EventType::DocumentAuthorizationFailed));
        assert_eq!(event.auth_failure_reason, AuthFailureReason::DocumentNotFound as u32);
    }

    #[test]
    fn event_emission_records_auth_failure_for_non_owner_change() {
        let (env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let other = Address::generate(&env);
        let err = client
            .try_change_owner(&other, &document_hash, &other)
            .unwrap_err()
            .unwrap();

        assert_eq!(err, ContractError::InvalidOwner);
        let count = client.get_document_event_count(&document_hash);
        assert!(count >= 2);
    }

    #[test]
    fn event_record_includes_timestamp() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert!(event.timestamp > 0);
    }

    #[test]
    fn auth_failure_reason_is_none_for_success_events() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);

        let event = client.get_document_event(&document_hash, &1).unwrap();
        assert_eq!(event.auth_failure_reason, NONE_REASON);
    }

    #[test]
    fn event_emission_records_document_owner_changed() {
        let (env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        let new_owner = Address::generate(&env);
        let record = client.change_owner(&owner, &document_hash, &new_owner);

        assert_eq!(record.owner, new_owner);
        let event = client.get_document_event(&document_hash, 2).unwrap();
        assert!(matches!(
            event.event_type,
            EventType::DocumentOwnerChanged
        ));
        assert_eq!(event.actor, owner);
    }

    #[test]
    fn event_sequence_ordering() {
        let (_env, client, issuer, owner, document_hash) = setup();

        client.register_document(&issuer, &owner, &document_hash);
        client.verify_document(&issuer, &document_hash).unwrap();
        client.verify_document(&issuer, &document_hash).unwrap();

        let event1 = client.get_document_event(&document_hash, 1).unwrap();
        let event2 = client.get_document_event(&document_hash, 2).unwrap();
        let event3 = client.get_document_event(&document_hash, 3).unwrap();
        assert_eq!(event1.sequence, 1);
        assert_eq!(event2.sequence, 2);
        assert_eq!(event3.sequence, 3);
    }

    #[test]
    fn get_document_event_returns_none_for_missing() {
        let (_env, client, _issuer, _owner, document_hash) = setup();

        let event = client.get_document_event(&document_hash, 1);
        assert!(event.is_none());
    }
}