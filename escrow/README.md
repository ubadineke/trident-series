# Escrow Program - Invariants & Stateful Fuzzing

This project is part of the **Trident Security & Fuzzing YouTube Playlist**.

## Purpose

The **Escrow Program** serves as our advanced testing playground. While basic fuzzing throws random numbers at single instructions, real-world smart contracts usually break when multiple state transitions interact in unexpected ways.

We use this codebase in the series to teach:
- **Invariant Design**: How to write rules that must always hold true (Conservation, State Machine, and Authorization invariants).
- **Stateful Fuzzing**: How to use Trident to explore sequential execution paths (e.g., `Initialize -> Fund -> Cancel`).
- **Cross-flow State Tracking**: How to use AddressStorage infrastructure to track state variables across multiple instructions to ensure complex transitions behave securely.

## What You Will Learn
In this module, you will learn how to identify state-transition bugs that would pass standard unit tests but fail under heavy, randomized execution sequences. You will see how invariants act as a force field around your core program logic.
