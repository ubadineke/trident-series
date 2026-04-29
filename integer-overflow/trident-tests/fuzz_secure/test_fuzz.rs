use fuzz_accounts::*;
use trident_fuzz::fuzzing::*;
mod fuzz_accounts;
mod types;
use types::*;

use crate::types::secure::{CreateUserAccountInstruction, CreateUserAccountInstructionAccounts, CreateUserAccountInstructionData, DepositInstruction, DepositInstructionAccounts, DepositInstructionData, InitializeVaultInstruction, InitializeVaultInstructionAccounts, InitializeVaultInstructionData, WithdrawInstruction, WithdrawInstructionAccounts, WithdrawInstructionData};

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
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        // Perform any initialization here, this method will be executed
        // at the start of each iteration

        //Get/Init Accounts
        let authority =  self.fuzz_accounts.authority.insert(&mut self.trident, None);
        let vault = self.fuzz_accounts.vault.insert(&mut self.trident, Some(PdaSeeds { seeds: &[b"vault"], program_id: secure::program_id()}));
        let user = self.fuzz_accounts.user.insert(&mut self.trident, None);
        let user_account = self.fuzz_accounts.user_account.insert(&mut self.trident, Some(PdaSeeds { seeds: &[b"user", user.as_ref()], program_id: secure::program_id()}));

        self.trident.airdrop(&authority, 1_000_000_000_000);
        self.trident.airdrop(&vault, 1_000_000_000);
        self.trident.airdrop(&user, 1_000_000_000);
        self.trident.airdrop(&user_account, 1_000_000_000);


        //Construct Instruction Data
        let input = self.trident.random_from_range(0..u32::MAX);

        //Construct Transaction
        let ix = InitializeVaultInstruction::data(InitializeVaultInstructionData::new(input.into())).accounts(InitializeVaultInstructionAccounts::new(authority, vault)).instruction();

        let create_user_ix = CreateUserAccountInstruction::data(CreateUserAccountInstructionData::new()).accounts(CreateUserAccountInstructionAccounts::new(user, user_account)).instruction();

        //Execute Transaction
        let _ = self.trident.process_transaction(&[ix], Some("InitializeVault"));
        let _ = self.trident.process_transaction(&[create_user_ix], Some("CreateUserAccount"));

        //Invariant Checks
    }

    #[flow]
    fn flow1(&mut self) {
        // Perform logic which is meant to be fuzzed
        // This flow is selected randomly from other flows

        //DEPOSIT TO VAULT
        //Get Accounts
        let user = self.fuzz_accounts.user.get(&mut self.trident).unwrap();
        let user_account = self.fuzz_accounts.user_account.get(&mut self.trident).unwrap();
        let vault = self.fuzz_accounts.vault.get(&mut self.trident).unwrap();

        //State Instruction Data
        let input =  self.trident.random_from_range(0..u32::MAX);  

        //CONSTRUCT INSTRUCTION
        let ix = DepositInstruction::data(DepositInstructionData::new(input.into())).accounts(DepositInstructionAccounts::new(user, user_account, vault)).instruction();

        //Execute Transaction
        let _ = self.trident.process_transaction(&[ix], Some("Deposit"));


        //INvariant Checks
    }

    #[flow]
    fn flow2(&mut self) {
        // Perform logic which is meant to be fuzzed
        // This flow is selected randomly from other flows

        //WITHDRAW FROM VAULT
        //Get Accounts
        let user = self.fuzz_accounts.user.get(&mut self.trident).unwrap();
        let user_account = self.fuzz_accounts.user_account.get(&mut self.trident).unwrap();
        let vault = self.fuzz_accounts.vault.get(&mut self.trident).unwrap();

        //State Instruction Data
        let input =  self.trident.random_from_range(0..u32::MAX);

        //Construct Instruction
        let ix = WithdrawInstruction::data(WithdrawInstructionData::new(input.into())).accounts(WithdrawInstructionAccounts::new(user, user_account, user, vault)).instruction();

        //Execute Transaction
        let result = self.trident.process_transaction(&[ix], Some("Withdraw"));


    }

    #[end]
    fn end(&mut self) {
        // Perform any cleanup here, this method will be executed
        // at the end of each iteration
    }
}

fn main() {
    FuzzTest::fuzz(100, 10);
}
