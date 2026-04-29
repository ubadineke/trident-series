use trident_fuzz::fuzzing::*;

/// Storage for all account addresses used in fuzz testing.
///
/// This struct serves as a centralized repository for account addresses,
/// enabling their reuse across different instruction flows and test scenarios.
///
/// Docs: https://ackee.xyz/trident/docs/latest/trident-api-macro/trident-types/fuzz-accounts/
#[derive(Default)]
pub struct AccountAddresses {
    pub canceller: AddressStorage,

    pub escrow: AddressStorage,

    pub vault: AddressStorage,

    pub depositor: AddressStorage,

    pub taker: AddressStorage,

    pub system_program: AddressStorage,

    pub counterparty: AddressStorage,
}
