# Integer Overflow/Underflow - Fuzzing Mechanics

This project is part of the **Trident Security & Fuzzing YouTube Playlist**.

🎥 **Watch the associated videos for this module:**
- [Live Fuzzing 1](https://youtu.be/sRNdlQtoH6s?si=PgSrXUsRoFj8nyJT)
- [Live Fuzzing 2](https://youtu.be/Dg7nsUKWi7s?si=GBW72no5kqYcCPdY)

## Purpose

The **Integer Overflow/Underflow** module acts as the introduction to writing regular fuzz tests with Trident. Before tackling complex multi-instruction states, it's essential to master the mechanics of building a fuzzer harness.

We use this codebase in the series to teach:
- **Framework Basics**: Setting up your first Trident fuzzing harness and building standard flows.
- **Handling Randomization**: How Trident generates randomized inputs and why that breaks untested assumptions.
- **Vulnerable vs. Secure Outcomes**: Comparing a vulnerable `wrapping_sub` implementation with a secure `checked_sub` implementation, and studying how Trident interprets on-chain instruction outcomes.

## What You Will Learn
This module simplifies the program logic so you can focus entirely on the *testing tools*. By the end of this example, you will understand how to construct the fuzz test suite, set baseline edge-case bounds (like `u32::MAX`), and interpret Trident's pass/fail logs correctly.
