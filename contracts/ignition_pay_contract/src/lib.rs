#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, Map, String, Symbol, Vec};
use crate::MultiOracleContractClient;

const MAX_CALLS_PER_LEDGER: u32 = 5;
const CONTRACT_VERSION: &str = "0.1.0";
const VERSION_KEY: &str = "contract_version";
const ADMIN_KEY: &str = "admin";
const AUTHORIZATIONS_KEY: &str = "authorizations";
const RATE_LIMIT_KEY: &str = "rate_limit";
const KYC_STATUS_KEY: &str = "kyc_status";
const PENDING_UPGRADE_KEY: &str = "pending_upgrade";
const PENDING_VERSION_KEY: &str = "pending_version";
const DEFAULT_MAX_STALENESS_SECONDS: u64 = 300;
/// Upper bound on a governance proposal title, in UTF-8 bytes. Titles are
/// stored as `String` (not `Symbol`) so human-readable text fits, but are still
/// bounded to keep instance storage small.
const MAX_PROPOSAL_TITLE_BYTES: u32 = 256;
/// Default maximum move (in basis points) a single `PriceFeedContract`
/// observation may make relative to the previous accepted price.
const DEFAULT_MAX_PRICE_DEVIATION_BPS: u32 = 5_000;

#[contracttype]
#[derive(Clone)]
pub struct PriceObservation {
    pub price: u64,
    pub timestamp: u64,
    pub oracle: Address,
    pub ledger: u32,
}

#[contract]
pub struct IgnitionPayContract;

#[contractimpl]
impl IgnitionPayContract {
    /// Initialize the contract with an admin address.
    /// This should be called exactly once after deployment.
    pub fn initialize(env: Env, admin: Address) {
        // Guard against re-initialization
        if env.storage().instance().has(&Symbol::new(&env, VERSION_KEY)) {
            panic!("Contract already initialized");
        }

        env.storage().instance().set(&Symbol::new(&env, ADMIN_KEY), &admin);
        env.storage().instance().set(&Symbol::new(&env, AUTHORIZATIONS_KEY), &Vec::<Address>::new(&env));
        env.storage().instance().set(&Symbol::new(&env, RATE_LIMIT_KEY), &Map::<Address, (u32, u32)>::new(&env));
        env.storage().instance().set(&Symbol::new(&env, KYC_STATUS_KEY), &Map::<Address, bool>::new(&env));
        env.storage().instance().set(&Symbol::new(&env, VERSION_KEY), &Symbol::new(&env, CONTRACT_VERSION));
    }

    fn check_rate_limit(&self, env: &Env, user: &Address) {
        let mut rate_limit: Map<Address, (u32, u32)> = env.storage().instance().get(&Symbol::new(&env, RATE_LIMIT_KEY)).unwrap_or_else(|| Map::new(env));
        let current_ledger = env.ledger().sequence();

        let (last_ledger, call_count) = rate_limit.get(user.clone()).unwrap_or((0, 0));

        if last_ledger == current_ledger {
            if call_count >= MAX_CALLS_PER_LEDGER {
                panic!("Rate limit exceeded");
            }
            rate_limit.set(user.clone(), (current_ledger, call_count + 1));
        } else {
            rate_limit.set(user.clone(), (current_ledger, 1));
        }

        env.storage().instance().set(&Symbol::new(&env, RATE_LIMIT_KEY), &rate_limit);
    }

    /// Set KYC status for a user. Only callable by admin.
    pub fn set_kyc_status(&self, env: &Env, user: &Address, kyc_completed: bool) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();

        self.check_rate_limit(&env, &admin);

        let mut kyc_status: Map<Address, bool> = env.storage().instance().get(&Symbol::new(&env, KYC_STATUS_KEY)).unwrap_or_else(|| Map::new(env));
        kyc_status.set(user.clone(), kyc_completed);
        env.storage().instance().set(&Symbol::new(&env, KYC_STATUS_KEY), &kyc_status);
    }

    /// Authorize a user. Requires admin auth and KYC completion.
    pub fn authorize(&self, env: Env, user: Address) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();

        self.check_rate_limit(&env, &admin);

        let kyc_status: Map<Address, bool> = env.storage().instance().get(&Symbol::new(&env, KYC_STATUS_KEY)).unwrap_or_else(|| Map::new(&env));
        if !kyc_status.get(user.clone()).unwrap_or(false) {
            panic!("KYC not completed");
        }

        let mut authorizations: Vec<Address> = env.storage().instance().get(&Symbol::new(&env, AUTHORIZATIONS_KEY)).unwrap_or_else(|| Vec::new(&env));
        authorizations.push_back(user);
        env.storage().instance().set(&Symbol::new(&env, AUTHORIZATIONS_KEY), &authorizations);
    }

    /// Revoke authorization for a user. Only callable by admin.
    pub fn revoke(&self, env: Env, user: Address) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();

        self.check_rate_limit(&env, &admin);

        let mut authorizations: Vec<Address> = env.storage().instance().get(&Symbol::new(&env, AUTHORIZATIONS_KEY)).unwrap_or_else(|| Vec::new(&env));
        if let Some(index) = authorizations.iter().position(|a| a == user) {
            authorizations.remove(index as u32);
        }
        env.storage().instance().set(&Symbol::new(&env, AUTHORIZATIONS_KEY), &authorizations);
    }

    /// Check if a user is authorized.
    pub fn is_authorized(env: Env, user: Address) -> bool {
        let authorizations: Vec<Address> = env.storage().instance().get(&Symbol::new(&env, AUTHORIZATIONS_KEY)).unwrap_or_else(|| Vec::new(&env));
        authorizations.contains(&user)
    }

    /// Enumerate authorized users with pagination.
    pub fn authorized_users(env: Env, offset: u32, limit: u32) -> Vec<Address> {
        let authorizations: Vec<Address> = env.storage().instance().get(&Symbol::new(&env, AUTHORIZATIONS_KEY)).unwrap_or_else(|| Vec::new(&env));
        let total = authorizations.len();
        let mut result = Vec::new(&env);
        if offset >= total || limit == 0 {
            return result;
        }
        let end = core::cmp::min(offset.saturating_add(limit), total);
        let mut i = offset;
        while i < end {
            if let Some(addr) = authorizations.get(i) {
                result.push_back(addr);
            }
            i += 1;
        }
        result
    }

    pub fn version(env: Env) -> Symbol {
        env.storage().instance().get(&Symbol::new(&env, VERSION_KEY)).unwrap_or_else(|| panic!("Version not set"))
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();
        env.storage().instance().set(&Symbol::new(&env, PENDING_UPGRADE_KEY), &new_wasm_hash);
        env.events().publish((Symbol::new(&env, "upgrade_initiated"), &admin), &new_wasm_hash);
    }

    pub fn upgrade_with_version(env: Env, new_wasm_hash: BytesN<32>, new_version: Symbol) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();
        env.storage().instance().set(&Symbol::new(&env, PENDING_UPGRADE_KEY), &new_wasm_hash);
        env.storage().instance().set(&Symbol::new(&env, PENDING_VERSION_KEY), &new_version);
        env.events().publish((Symbol::new(&env, "upgrade_initiated"), &admin), &new_wasm_hash);
    }

    pub fn apply_upgrade(env: Env) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, ADMIN_KEY)).unwrap_or_else(|| panic!("Admin not set"));
        admin.require_auth();
        let new_wasm_hash: BytesN<32> = env.storage().instance().get(&Symbol::new(&env, PENDING_UPGRADE_KEY)).unwrap_or_else(|| panic!("No pending upgrade"));
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        if let Some(new_version)
    
