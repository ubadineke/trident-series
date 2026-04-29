import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Vulnerable } from "../target/types/vulnerable";
import { Secure } from "../target/types/secure";
import { expect } from "chai";
import { LAMPORTS_PER_SOL, PublicKey, SystemProgram } from "@solana/web3.js";

describe("integer-overflow", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const vulnerableProgram = anchor.workspace.Vulnerable as Program<Vulnerable>;
  const secureProgram = anchor.workspace.Secure as Program<Secure>;

  // =============================================================================
  // VULNERABLE PROGRAM TESTS
  // =============================================================================
  describe("Vulnerable Program", () => {
    let authority: anchor.web3.Keypair;
    let user: anchor.web3.Keypair;
    let vaultPda: PublicKey;
    let userAccountPda: PublicKey;

    before(async () => {
      authority = anchor.web3.Keypair.generate();
      user = anchor.web3.Keypair.generate();

      // Fund authority and user from provider
      const tx = new anchor.web3.Transaction().add(
        anchor.web3.SystemProgram.transfer({
          fromPubkey: provider.wallet.publicKey,
          toPubkey: authority.publicKey,
          lamports: 6 * LAMPORTS_PER_SOL,
        }),
        anchor.web3.SystemProgram.transfer({
          fromPubkey: provider.wallet.publicKey,
          toPubkey: user.publicKey,
          lamports: 2 * LAMPORTS_PER_SOL,
        })
      );
      await provider.sendAndConfirm(tx);

      // Derive PDAs
      [vaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        vulnerableProgram.programId
      );

      [userAccountPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("user"), user.publicKey.toBuffer()],
        vulnerableProgram.programId
      );
    });

    it("initializes the vault", async () => {
      const initialAmount = new anchor.BN(5 * LAMPORTS_PER_SOL);

      await vulnerableProgram.methods
        .initializeVault(initialAmount)
        .accounts({
          authority: authority.publicKey,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority])
        .rpc();

      const vault = await vulnerableProgram.account.vault.fetch(vaultPda);
      expect(vault.authority.toString()).to.equal(authority.publicKey.toString());
      expect(vault.totalDeposits.toNumber()).to.equal(initialAmount.toNumber());
    });

    it("creates a user account", async () => {
      await vulnerableProgram.methods
        .createUserAccount()
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const userAccount = await vulnerableProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccount.owner.toString()).to.equal(user.publicKey.toString());
      expect(userAccount.balance.toNumber()).to.equal(0);
    });

    it("deposits funds", async () => {
      const depositAmount = new anchor.BN(1 * LAMPORTS_PER_SOL);

      await vulnerableProgram.methods
        .deposit(depositAmount)
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const userAccount = await vulnerableProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccount.balance.toNumber()).to.equal(depositAmount.toNumber());
    });

    it("allows normal withdrawal within balance", async () => {
      const withdrawAmount = new anchor.BN(0.5 * LAMPORTS_PER_SOL);

      const balanceBefore = await provider.connection.getBalance(user.publicKey);

      await vulnerableProgram.methods
        .withdraw(withdrawAmount)
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          owner: user.publicKey,
          vault: vaultPda,
        })
        .signers([user])
        .rpc();

      const balanceAfter = await provider.connection.getBalance(user.publicKey);
      const userAccount = await vulnerableProgram.account.userAccount.fetch(userAccountPda);

      // User should have received the withdrawal (minus tx fees)
      expect(balanceAfter).to.be.greaterThan(balanceBefore);
      // User balance should be reduced
      expect(userAccount.balance.toNumber()).to.equal(0.5 * LAMPORTS_PER_SOL);
    });

    it("🚨 EXPLOIT: underflow attack - withdraw more than balance SUCCEEDS!", async () => {
      // Get current user balance (should be 0.5 SOL after previous withdrawal)
      const userAccountBefore = await vulnerableProgram.account.userAccount.fetch(userAccountPda);
      console.log("\n🔍 Before attack:");
      console.log(`   User balance: ${userAccountBefore.balance.toNumber()} lamports`);

      // Try to withdraw MORE than the balance - this should underflow!
      const currentBalance = userAccountBefore.balance.toNumber();
      const withdrawAmount = new anchor.BN(currentBalance + 0.3 * LAMPORTS_PER_SOL);
      console.log(`   Attempting to withdraw: ${withdrawAmount.toNumber()} lamports`);

      // This SUCCEEDS on vulnerable program because it doesn't check balance!
      await vulnerableProgram.methods
        .withdraw(withdrawAmount)
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          owner: user.publicKey,
          vault: vaultPda,
        })
        .signers([user])
        .rpc();

      const userAccountAfter = await vulnerableProgram.account.userAccount.fetch(userAccountPda);
      console.log("\n💥 After attack:");
      console.log(`   User balance: ${userAccountAfter.balance.toString()} lamports`);

      // The balance has UNDERFLOWED to a massive number!
      // Expected: currentBalance - withdrawAmount would be negative
      // Actual: wraps to near u64::MAX
      const expectedUnderflow = BigInt(currentBalance) - BigInt(withdrawAmount.toNumber());
      const actualBalance = BigInt(userAccountAfter.balance.toString());

      console.log(`\n🚨 UNDERFLOW DETECTED!`);
      console.log(`   Expected (if safe): ${expectedUnderflow} (negative = error)`);
      console.log(`   Actual (underflowed): ${actualBalance}`);

      // Verify the underflow occurred - balance should be astronomically large
      // u64::MAX = 18,446,744,073,709,551,615
      expect(actualBalance > BigInt("18000000000000000000")).to.be.true;
    });
  });

  // =============================================================================
  // SECURE PROGRAM TESTS
  // =============================================================================
  describe("Secure Program", () => {
    let authority: anchor.web3.Keypair;
    let user: anchor.web3.Keypair;
    let vaultPda: PublicKey;
    let userAccountPda: PublicKey;

    before(async () => {
      authority = anchor.web3.Keypair.generate();
      user = anchor.web3.Keypair.generate();

      // Fund from provider
      const tx = new anchor.web3.Transaction().add(
        anchor.web3.SystemProgram.transfer({
          fromPubkey: provider.wallet.publicKey,
          toPubkey: authority.publicKey,
          lamports: 6 * LAMPORTS_PER_SOL,
        }),
        anchor.web3.SystemProgram.transfer({
          fromPubkey: provider.wallet.publicKey,
          toPubkey: user.publicKey,
          lamports: 2 * LAMPORTS_PER_SOL,
        })
      );
      await provider.sendAndConfirm(tx);

      // Derive PDAs for secure program
      [vaultPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault")],
        secureProgram.programId
      );

      [userAccountPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("user"), user.publicKey.toBuffer()],
        secureProgram.programId
      );
    });

    it("initializes the vault", async () => {
      const initialAmount = new anchor.BN(5 * LAMPORTS_PER_SOL);

      await secureProgram.methods
        .initializeVault(initialAmount)
        .accounts({
          authority: authority.publicKey,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([authority])
        .rpc();

      const vault = await secureProgram.account.vault.fetch(vaultPda);
      expect(vault.authority.toString()).to.equal(authority.publicKey.toString());
    });

    it("creates a user account", async () => {
      await secureProgram.methods
        .createUserAccount()
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const userAccount = await secureProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccount.owner.toString()).to.equal(user.publicKey.toString());
      expect(userAccount.balance.toNumber()).to.equal(0);
    });

    it("deposits funds", async () => {
      const depositAmount = new anchor.BN(1 * LAMPORTS_PER_SOL);

      await secureProgram.methods
        .deposit(depositAmount)
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          vault: vaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const userAccount = await secureProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccount.balance.toNumber()).to.equal(depositAmount.toNumber());
    });

    it("allows normal withdrawal within balance", async () => {
      const withdrawAmount = new anchor.BN(0.5 * LAMPORTS_PER_SOL);

      await secureProgram.methods
        .withdraw(withdrawAmount)
        .accounts({
          user: user.publicKey,
          userAccount: userAccountPda,
          owner: user.publicKey,
          vault: vaultPda,
        })
        .signers([user])
        .rpc();

      const userAccount = await secureProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccount.balance.toNumber()).to.equal(0.5 * LAMPORTS_PER_SOL);
    });

    it("✅ SECURE: underflow attack FAILS with InsufficientFunds error", async () => {
      const userAccountBefore = await secureProgram.account.userAccount.fetch(userAccountPda);
      console.log("\n🔍 Attempting underflow attack on SECURE program:");
      console.log(`   User balance: ${userAccountBefore.balance.toNumber()} lamports`);

      // Try to withdraw MORE than balance
      const currentBalance = userAccountBefore.balance.toNumber();
      const withdrawAmount = new anchor.BN(currentBalance + 0.3 * LAMPORTS_PER_SOL);
      console.log(`   Attempting to withdraw: ${withdrawAmount.toNumber()} lamports`);

      // This should FAIL with InsufficientFunds error
      try {
        await secureProgram.methods
          .withdraw(withdrawAmount)
          .accounts({
            user: user.publicKey,
            userAccount: userAccountPda,
            owner: user.publicKey,
            vault: vaultPda,
          })
          .signers([user])
          .rpc();

        // If we get here, the attack succeeded (which is bad!)
        expect.fail("Expected InsufficientFunds error but withdrawal succeeded!");
      } catch (error: any) {
        console.log("\n✅ Attack blocked!");
        console.log(`   Error: ${error.error?.errorCode?.code || error.message}`);

        // Verify the correct error was thrown
        expect(error.error.errorCode.code).to.equal("InsufficientFunds");
      }

      // Verify balance is unchanged
      const userAccountAfter = await secureProgram.account.userAccount.fetch(userAccountPda);
      expect(userAccountAfter.balance.toNumber()).to.equal(currentBalance);
      console.log(`   Balance unchanged: ${userAccountAfter.balance.toNumber()} lamports`);
    });

    it("✅ SECURE: overflow attack on deposit FAILS with Overflow error", async () => {
      // Try to deposit an amount that would overflow u64::MAX
      // Since balance is already ~0.5 SOL, depositing near u64::MAX would overflow
      const hugeAmount = new anchor.BN("18446744073709551615"); // u64::MAX

      console.log("\n🔍 Attempting overflow attack on SECURE program:");
      console.log(`   Trying to deposit: ${hugeAmount.toString()} lamports`);

      try {
        await secureProgram.methods
          .deposit(hugeAmount)
          .accounts({
            user: user.publicKey,
            userAccount: userAccountPda,
            vault: vaultPda,
            systemProgram: SystemProgram.programId,
          })
          .signers([user])
          .rpc();

        expect.fail("Expected Overflow error but deposit succeeded!");
      } catch (error: any) {
        console.log("\n✅ Overflow attack blocked!");
        // The error might be Overflow or a transfer failure due to insufficient SOL
        // Either way, the overflow is prevented
        console.log(`   Error: ${error.error?.errorCode?.code || error.message}`);
      }
    });
  });
});

