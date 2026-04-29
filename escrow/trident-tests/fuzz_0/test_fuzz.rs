use fuzz_accounts::*;
use trident_fuzz::fuzzing::*;
use ::escrow::entry as escrow_entrypoint;

mod fuzz_accounts;
mod types;

use types::escrow::{
    program_id, CancelEscrowInstruction, CancelEscrowInstructionAccounts, CancelEscrowInstructionData,
    ExchangeInstruction, ExchangeInstructionAccounts, ExchangeInstructionData, FundEscrowInstruction,
    FundEscrowInstructionAccounts, FundEscrowInstructionData, InitializeEscrowInstruction,
    InitializeEscrowInstructionAccounts, InitializeEscrowInstructionData,
};

use crate::types::EscrowState;

// We manually mirror the Enum from the program for our invariants
#[repr(u8)]
pub enum EscrowStatus {
    Initialized = 0,
    Funded = 1,
    Exchanged = 2,
    Cancelled = 3,
}

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[derive(FuzzTestMethods)]
struct FuzzTest {
    /// Trident client for interacting with the Solana program
    trident: Trident,
    /// Storage for all account addresses used in fuzz testing
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self {
        let mut trident = Trident::default();
        // Deploy through the entrypoint for coverage
        let program = TridentEntrypoint::new(
            your_program::ID,
            None,
            processor!(your_entrypoint)
        );
        trident.deploy_entrypoint(program);
        Self {
            trident,
            fuzz_accounts: AccountAddresses::default(),
        }
        // Self {
        //     trident: Trident::default(),
        //     fuzz_accounts: AccountAddresses::default(),
        // }
    }

    #[init]
    fn start(&mut self) {
        // Setup Depositor
        let depositor = self.fuzz_accounts.depositor.insert(&mut self.trident, None);
        self.trident.airdrop(&depositor, 1000 * LAMPORTS_PER_SOL);

        // Setup Counterparty (Taker)
        let counterparty = self.fuzz_accounts.counterparty.insert(&mut self.trident, None);
        self.trident.airdrop(&counterparty, 10 * LAMPORTS_PER_SOL);
        
        // Taker is usually the counterparty, so we seed the taker pool
        self.fuzz_accounts.taker.insert_with_address(counterparty);
        
        // Canceller pool can include valid parties or others
        self.fuzz_accounts.canceller.insert_with_address(counterparty);
        self.fuzz_accounts.canceller.insert_with_address(depositor);

        // Derive Escrow PDA ahead of time
        let escrow = self.fuzz_accounts.escrow.insert(
            &mut self.trident,
            Some(PdaSeeds {
                seeds: &[b"escrow", depositor.as_ref()],
                program_id: program_id(),
            }),
        );

        // Derive Vault PDA ahead of time
        let _vault = self.fuzz_accounts.vault.insert(
            &mut self.trident,
            Some(PdaSeeds {
                seeds: &[b"vault", escrow.as_ref()],
                program_id: program_id(),
            }),
        );
    }

    #[flow]
    fn flow_initialize(&mut self) {
        let depositor = self.fuzz_accounts.depositor.get(&mut self.trident);
        let escrow = self.fuzz_accounts.escrow.get(&mut self.trident);
        let counterparty = self.fuzz_accounts.counterparty.get(&mut self.trident);

        let amount = self.trident.random_from_range(1..100u64) * LAMPORTS_PER_SOL;

        let ix = InitializeEscrowInstruction::data(InitializeEscrowInstructionData::new(amount))
            .accounts(InitializeEscrowInstructionAccounts::new(
                depositor.unwrap(),
                escrow.unwrap(),
                counterparty.unwrap(),
            ))
            .instruction();

        let _ = self.trident.process_transaction(&[ix], Some("InitializeEscrow"));
    }

    #[flow]
    fn flow_fund(&mut self) {
        let depositor = self.fuzz_accounts.depositor.get(&mut self.trident).unwrap();
        let escrow = self.fuzz_accounts.escrow.get(&mut self.trident).unwrap();
        let vault = self.fuzz_accounts.vault.get(&mut self.trident).unwrap();


          // 1. BEFORE: Capture state
    let escrow_before = self.trident
        .get_account_with_type::<EscrowState>(&escrow, 8);
    let amount_before = escrow_before
        .as_ref()
        .map(|e| e.amount)
        .unwrap_or(0);

    // Random amount with edge values
    let amount = match self.trident.random_from_range(0..4u8) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        // Match the 1..100 SOL range used during initialization
        _ => self.trident.random_from_range(1..100u64) * LAMPORTS_PER_SOL,
    };

        let ix = FundEscrowInstruction::data(FundEscrowInstructionData::new(amount))
            .accounts(FundEscrowInstructionAccounts::new(
                depositor,
                escrow,
                vault,
            ))
            .instruction();

        let result = self.trident.process_transaction(&[ix], Some("FundEscrow"));

    //  3. AFTER: Verify conservation invariant
    // Using if let Some() means we check this whether the transaction succeeded or failed
    if let Some(escrow_after) = self.trident.get_account_with_type::<EscrowState>(&escrow, 8) {

        // Conservation: The recorded amount MUST ALWAYS equal the initialized amount before the transaction.
        // It should never be arbitrary overwritten.
        assert_eq!(
            amount_before,
            escrow_after.amount,
            "CONSERVATION VIOLATION: Escrow amount mutated! Expected {}, Found {}",
            amount_before, escrow_after.amount
        );
     }
    }

    #[flow]
    fn flow_exchange(&mut self) {
        let taker = self.fuzz_accounts.taker.get(&mut self.trident).unwrap();
        let escrow = self.fuzz_accounts.escrow.get(&mut self.trident).unwrap();
        let vault = self.fuzz_accounts.vault.get(&mut self.trident).unwrap();

        // Capture BEFORE state
        let escrow_before = self.trident.get_account_with_type::<EscrowState>(&escrow, 8);
        let status_before = escrow_before.as_ref().map(|e| e.status);

        let ix = ExchangeInstruction::data(ExchangeInstructionData::new())
            .accounts(ExchangeInstructionAccounts::new(
                taker,
                escrow,
                vault,
            ))
            .instruction();

        let result = self.trident.process_transaction(&[ix], Some("Exchange"));

        // INVARIANT 2: State Machine Rules via Negative Testing
        // If the Escrow was NOT Funded prior to transaction...
        if let Some(status) = status_before {
            if status != EscrowStatus::Funded as u8 {
                // ...Then the Exchange instruction MUST have failed natively!
                assert!(
                    !result.is_success(),
                    "STATE MACHINE VIOLATION: Exchange succeeded even though the Escrow was in Status {}! Expected it to fail because it wasn't Funded (1).",
                    status
                );
            }
        }
    }

    #[flow]
    fn flow_cancel(&mut self) {
        let canceller = self.fuzz_accounts.canceller.get(&mut self.trident).unwrap();
        let escrow = self.fuzz_accounts.escrow.get(&mut self.trident).unwrap();
        let vault = self.fuzz_accounts.vault.get(&mut self.trident).unwrap();
        let depositor = self.fuzz_accounts.depositor.get(&mut self.trident).unwrap();

        // 1. BEFORE: Capture the exact state of the escrow before the transaction
        let escrow_before = self.trident.get_account_with_type::<EscrowState>(&escrow, 8);
        let status_before = escrow_before.as_ref().map(|e| e.status);

        // 2. EXECUTE: Anyone tries to cancel the escrow
        let ix = CancelEscrowInstruction::data(CancelEscrowInstructionData::new())
            .accounts(CancelEscrowInstructionAccounts::new(
                canceller,
                escrow,
                vault,
                depositor,
            ))
            .instruction();

        let _ = self.trident.process_transaction(&[ix], Some("Cancel"));

        // 3. AFTER: Verify State Isolation Invariant
        // Rule: If the person who called cancel is NOT the original depositor...
        if canceller != depositor {
            let escrow_after = self.trident.get_account_with_type::<EscrowState>(&escrow, 8);
            let status_after = escrow_after.as_ref().map(|e| e.status);
            
            // ...then the Escrow state MUST remain exactly as it was. 
            // If the status changed to Cancelled, an attacker successfully griefed the protocol!
            assert_eq!(
                status_before, status_after,
                "AUTHORIZATION VIOLATION: A random actor ({}) successfully altered the state of an Escrow owned by {}",
                canceller, depositor
            );
        }
    }

    #[end]
    fn end(&mut self) {}
}
fn main() {
    FuzzTest::fuzz(1000, 10);
}
