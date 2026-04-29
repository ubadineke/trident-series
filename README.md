# Trident Fuzzing Series - YouTube Companion Repository

Welcome to the companion repository for the **Trident Security & Fuzzing YouTube Playlist**! 

This codebase was specifically designed to provide developers with hands-on, replicable examples to follow along with the video series. The goal of this repository is to break down the mechanics of the Trident fuzzing framework in Solana and teach you how to write professional-grade fuzz tests for your smart contracts.

## What's Inside?

This directory contains two specific Solana projects designed to teach different levels of security testing:

1. **`integer-overflow/`**: A foundational module to teach regular fuzz testing mechanics.
2. **`escrow/`**: A more complex module focused on state machine limits and designing proper invariants.

## How to Follow Along

This repository serves as the definitive reference code for the series. We recommend having this repository open while watching the playlist. You can inspect the target programs, explore the intentionally placed vulnerabilities, run the Trident fuzzer, and see the exact same output that is presented in the videos.

We provide both `vulnerable` and `secure` versions (or specific flows) to demonstrate the before-and-after of catching bugs with Trident.
