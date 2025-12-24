# Contributing to PQ-BANK

Thank you for your interest in contributing to **PQ-BANK: Quantum-Resistant Wallet & Key Management System**.

This project demonstrates **post-quantum cryptographic engineering**, and contributions are expected to meet high standards of correctness, security, and documentation.

---

## Ways to Contribute

You may contribute by:

- Improving documentation or diagrams
- Adding tests or benchmarks
- Enhancing cryptographic workflows
- Improving GUI/UX (eframe/egui)
- Refactoring for clarity or safety
- Reporting bugs or vulnerabilities
- Suggesting architectural improvements

---

## Development Guidelines

### Code Quality

- Follow **Rustfmt** and **Clippy**
- Write clear, readable, and idiomatic Rust
- Prefer explicitness over cleverness in cryptographic code
- Avoid unsafe code unless absolutely necessary (and justify it)

### Cryptography Rules (Mandatory)

- **Never roll your own cryptography**
- Use only well-reviewed crates and primitives
- Do not modify cryptographic parameters without explanation
- All crypto-related changes must include:
  - Rationale
  - Threat considerations
  - References (NIST / RFC / papers)

---

## Branching & Workflow

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
````

3. Make atomic, well-documented commits
4. Run formatting and checks:

   ```bash
   cargo fmt
   cargo clippy
   cargo test
   ```
5. Push to your fork
6. Open a Pull Request (PR)

---

## Pull Request Requirements

Each PR **must include**:

* Clear description of changes
* Motivation and impact analysis
* Security implications (if applicable)
* Tests or justification if tests are not feasible

PRs will be reviewed for:

* Code quality and correctness
* Cryptographic safety
* Reproducibility
* Alignment with project goals

---

## Experimental Code

If your contribution is experimental:

* Clearly label it as such
* Isolate it behind feature flags where possible
* Do not enable insecure defaults

---

## Licensing

By contributing, you agree that your work will be licensed under the **MIT License**, consistent with the rest of the project.

---

Thank you for helping advance quantum-resistant systems 🚀
