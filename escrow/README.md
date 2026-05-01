# Escrow Program - Invariants & Stateful Fuzzing

This project is part of the **Trident Security & Fuzzing YouTube Playlist**.

🎥 **Watch the associated video for this module:**
- [Writing Invariants](https://youtu.be/kRK31lOLnGo?si=vxjtx28qqtlQwlZI)

## Purpose

The **Escrow Program** serves as our advanced testing playground. While basic fuzzing throws random numbers at single instructions, real-world smart contracts usually break when multiple state transitions interact in unexpected ways.

We use this codebase in the series to teach:
- **Invariant Design**: How to write rules that must always hold true (Conservation, State Machine, and Authorization invariants).
- **Stateful Fuzzing**: How to use Trident to explore sequential execution paths (e.g., `Initialize -> Fund -> Cancel`).
- **Cross-flow State Tracking**: How to use AddressStorage infrastructure to track state variables across multiple instructions to ensure complex transitions behave securely.

## What You Will Learn
In this module, you will learn how to identify state-transition bugs that would pass standard unit tests but fail under heavy, randomized execution sequences. You will see how invariants act as a force field around your core program logic.

> **💡 Note:** The `programs/escrow/src/lib.rs` file is intentionally commented with obvious bugs to demonstrate how Trident catches them. 

### Highlighted Invariants (`test_fuzz.rs`)
The test harness (`test_fuzz.rs`) demonstrates three core types of invariants:
1. **Conservation Invariant**: Ensures the recorded escrow amount strictly equals the initialized amount and is never arbitrarily overwritten during funding.
2. **State Machine Invariant**: Verifies that the `Exchange` instruction strictly fails if the contract wasn't currently in the `Funded` state.
3. **Authorization/Isolation Invariant**: Confirms that if a user other than the original depositor attempts to call the `Cancel` instruction, the state remains unchanged.
