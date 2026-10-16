# Changelog

## v1.1.0 — 2026-10-16

- Add optional expected issuer (`iss`) and audience (`aud`) fields.
- Compare strings exactly and support membership in string-only audience arrays.
- Show match, mismatch, missing and invalid results separately from signature verification and the existing security verdict.
- Recompute on input and clear expectations with the token.
- Keep processing local without adding dependencies, persistence or service calls.
- Remove external Google Fonts loading; use the existing system-font fallback.
- Expand the Node test suite from 12 to 26 passing tests.
