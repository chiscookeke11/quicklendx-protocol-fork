use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, BytesN, Env, Symbol, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MultisigError {
    InvalidThreshold = 1,
    NotEnoughSignatures = 2,
    DuplicateSignature = 3,
    InvalidOwnerIndex = 4,
    AlreadyInitialized = 5,
    OperationExists = 6,
    OperationNotFound = 7,
    OperationExpired = 8,
    OperationExecuted = 9,
    InvalidNonce = 10,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSignature {
    pub owner_index: u32,
    pub signature: BytesN<64>,
}

const OWNERS_KEY: Symbol = symbol_short!("owners");
const THRESHOLD_KEY: Symbol = symbol_short!("thresh");
const NONCE_KEY: Symbol = symbol_short!("nonce");
const OP_PREFIX: Symbol = symbol_short!("ms_op");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultisigOperation {
    pub message_hash: BytesN<32>,
    pub nonce: u64,
    pub expires_at_ledger: u32,
    pub approvals: Vec<u32>,
    pub executed: bool,
}

fn operation_key(hash: &BytesN<32>) -> (Symbol, BytesN<32>) {
    (OP_PREFIX, hash.clone())
}

fn verify_signatures(
    env: &Env,
    message_hash: &BytesN<32>,
    signatures: &Vec<OwnerSignature>,
    owners: &Vec<BytesN<32>>,
) -> Result<Vec<u32>, MultisigError> {
    let mut seen = Vec::new(env);
    for sig in signatures.iter() {
        if sig.owner_index >= owners.len() {
            return Err(MultisigError::InvalidOwnerIndex);
        }
        if seen.contains(sig.owner_index) {
            return Err(MultisigError::DuplicateSignature);
        }
        let key = owners.get(sig.owner_index).ok_or(MultisigError::InvalidOwnerIndex)?;
        env.crypto().ed25519_verify(&key, &message_hash.clone().into(), &sig.signature);
        seen.push_back(sig.owner_index);
    }
    Ok(seen)
}

#[cfg(not(target_arch = "wasm32"))]
#[contract]
pub struct MultisigContract;

#[cfg(not(target_arch = "wasm32"))]
#[contractimpl]
impl MultisigContract {
    pub fn initialize(
        env: Env,
        owners: Vec<BytesN<32>>,
        threshold: u32,
    ) -> Result<(), MultisigError> {
        if env.storage().instance().has(&OWNERS_KEY) {
            return Err(MultisigError::AlreadyInitialized);
        }
        let n = owners.len();
        // Quorum threshold must be in range [1, N-1]
        // This implicitly requires N >= 2, because if N <= 1, threshold >= N will always hold
        // since threshold must be >= 1.
        if threshold < 1 || threshold >= n {
            return Err(MultisigError::InvalidThreshold);
        }

        env.storage().instance().set(&OWNERS_KEY, &owners);
        env.storage().instance().set(&THRESHOLD_KEY, &threshold);

        Ok(())
    }

    /// Propose an operation. The first threshold signatures are verified against
    /// the operation hash, and the supplied nonce must be the next sequence.
    pub fn propose_op(
        env: Env,
        message_hash: BytesN<32>,
        nonce: u64,
        expires_at_ledger: u32,
        signatures: Vec<OwnerSignature>,
    ) -> Result<(), MultisigError> {
        let threshold: u32 = env.storage().instance().get(&THRESHOLD_KEY).ok_or(MultisigError::InvalidThreshold)?;
        let owners: Vec<BytesN<32>> = env.storage().instance().get(&OWNERS_KEY).ok_or(MultisigError::InvalidOwnerIndex)?;
        if env.storage().instance().has(&operation_key(&message_hash)) { return Err(MultisigError::OperationExists); }
        if expires_at_ledger <= env.ledger().sequence() { return Err(MultisigError::OperationExpired); }
        let expected: u64 = env.storage().instance().get(&NONCE_KEY).unwrap_or(0);
        if nonce != expected { return Err(MultisigError::InvalidNonce); }
        let approvals = verify_signatures(&env, &message_hash, &signatures, &owners)?;
        if approvals.len() < threshold { return Err(MultisigError::NotEnoughSignatures); }
        let op = MultisigOperation { message_hash: message_hash.clone(), nonce, expires_at_ledger, approvals, executed: false };
        env.storage().persistent().set(&operation_key(&message_hash), &op);
        env.storage().persistent().extend_ttl(&operation_key(&message_hash), 100, 1000);
        env.storage().instance().set(&NONCE_KEY, &(expected.saturating_add(1)));
        Ok(())
    }

    /// Add one or more owner approvals to an existing, unexpired operation.
    pub fn approve_op(
        env: Env,
        message_hash: BytesN<32>,
        signatures: Vec<OwnerSignature>,
    ) -> Result<(), MultisigError> {
        let owners: Vec<BytesN<32>> = env.storage().instance().get(&OWNERS_KEY).ok_or(MultisigError::InvalidOwnerIndex)?;
        let key = operation_key(&message_hash);
        let mut op: MultisigOperation = env.storage().persistent().get(&key).ok_or(MultisigError::OperationNotFound)?;
        if op.executed { return Err(MultisigError::OperationExecuted); }
        if env.ledger().sequence() > op.expires_at_ledger { return Err(MultisigError::OperationExpired); }
        let new_approvals = verify_signatures(&env, &message_hash, &signatures, &owners)?;
        for index in new_approvals.iter() {
            if op.approvals.contains(index) { return Err(MultisigError::DuplicateSignature); }
            op.approvals.push_back(index);
        }
        env.storage().persistent().set(&key, &op);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        Ok(())
    }

    /// Consume an operation once its threshold has approved it.
    pub fn execute_op(env: Env, message_hash: BytesN<32>) -> Result<(), MultisigError> {
        let threshold: u32 = env.storage().instance().get(&THRESHOLD_KEY).ok_or(MultisigError::InvalidThreshold)?;
        let key = operation_key(&message_hash);
        let mut op: MultisigOperation = env.storage().persistent().get(&key).ok_or(MultisigError::OperationNotFound)?;
        if op.executed { return Err(MultisigError::OperationExecuted); }
        if env.ledger().sequence() > op.expires_at_ledger { return Err(MultisigError::OperationExpired); }
        if op.approvals.len() < threshold { return Err(MultisigError::NotEnoughSignatures); }
        op.executed = true;
        env.storage().persistent().set(&key, &op);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        Ok(())
    }

    /// Rotate the signer set only when the supplied operation has been
    /// approved and consumed by the current threshold.
    pub fn rotate_signers(
        env: Env,
        operation_hash: BytesN<32>,
        new_owners: Vec<BytesN<32>>,
        new_threshold: u32,
    ) -> Result<(), MultisigError> {
        let op: MultisigOperation = env.storage().persistent().get(&operation_key(&operation_hash)).ok_or(MultisigError::OperationNotFound)?;
        if !op.executed { return Err(MultisigError::NotEnoughSignatures); }
        if new_threshold == 0 || new_threshold >= new_owners.len() { return Err(MultisigError::InvalidThreshold); }
        env.storage().instance().set(&OWNERS_KEY, &new_owners);
        env.storage().instance().set(&THRESHOLD_KEY, &new_threshold);
        Ok(())
    }

    pub fn verify_op(
        env: Env,
        message_hash: BytesN<32>,
        signatures: Vec<OwnerSignature>,
    ) -> Result<(), MultisigError> {
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&THRESHOLD_KEY)
            .ok_or(MultisigError::InvalidThreshold)?;

        if signatures.len() < threshold {
            return Err(MultisigError::NotEnoughSignatures);
        }

        let owners: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&OWNERS_KEY)
            .ok_or(MultisigError::InvalidOwnerIndex)?;

        let mut seen_owners = Vec::new(&env);

        for sig in signatures.iter() {
            let index = sig.owner_index;
            if index >= owners.len() {
                return Err(MultisigError::InvalidOwnerIndex);
            }
            if seen_owners.contains(index) {
                return Err(MultisigError::DuplicateSignature);
            }
            seen_owners.push_back(index);

            let public_key = owners.get(index).unwrap();
            // Cryptographically verify signature
            env.crypto()
                .ed25519_verify(&public_key, &message_hash.clone().into(), &sig.signature);
        }

        Ok(())
    }
}
