# Implementation Plan: GitClaw SDK

## Overview

This implementation plan covers the development of official GitClaw SDKs for Python (primary), TypeScript/Node, and Rust. Each SDK follows the same logical architecture while adhering to language-specific idioms.

## Tasks

- [x] 1. Python SDK - Core Infrastructure
  - [x] 1.1 Set up Python SDK project structure
    - Create `sdk/python/` directory with pyproject.toml
    - Configure pytest, hypothesis, mypy, ruff
    - Set up package structure: `gitclaw/`, `gitclaw/types/`, `gitclaw/testing/`
    - _Requirements: 14.1, 14.2_ | _Design: DR-6_

  - [x] 1.2 Implement JCS Canonicalizer
    - Create `gitclaw/canonicalize.py` with JCSCanonicalizer class
    - Implement key sorting by UTF-16 code units
    - Implement number formatting (shortest representation)
    - Implement string escaping (minimal JSON escaping)
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_ | _Design: DR-2_

  - [x] 1.3 Write property test for JCS canonicalization round-trip
    - **Property 2: JCS canonicalization round-trip**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5** | **Design: DR-2**

  - [x] 1.4 Implement Ed25519 Signer
    - Create `gitclaw/signers.py` with Ed25519Signer class
    - Implement from_pem_file, from_pem, from_bytes methods
    - Implement generate() for keypair generation
    - Use cryptography library for Ed25519 operations
    - _Requirements: 2.1, 2.3, 2.7_ | _Design: DR-1_

  - [x] 1.5 Write property test for Ed25519 key loading round-trip
    - **Property 12: Ed25519 key loading round-trip**
    - **Validates: Requirements 2.1, 2.3** | **Design: DR-1**

  - [x] 1.6 Implement ECDSA P-256 Signer
    - Add EcdsaSigner class to `gitclaw/signers.py`
    - Implement from_pem_file, from_pem methods
    - Implement generate() for keypair generation
    - _Requirements: 2.2, 2.3_ | _Design: DR-1_

  - [x] 1.7 Write property test for ECDSA key loading round-trip
    - **Property 13: ECDSA key loading round-trip**
    - **Validates: Requirements 2.2, 2.3** | **Design: DR-1**


- [x] 2. Python SDK - Signature and Transport
  - [x] 2.1 Implement Signature Envelope Builder
    - Create `gitclaw/envelope.py` with SignatureEnvelope dataclass
    - Implement EnvelopeBuilder with build() method
    - Generate UUID v4 nonces automatically
    - _Requirements: 2.4, 4.1, 4.2_ | _Design: DR-3_

  - [x] 2.2 Implement signature generation flow
    - Create `gitclaw/signing.py` with sign_envelope() function
    - Canonicalize envelope using JCSCanonicalizer
    - Compute SHA256 hash of canonical JSON
    - Sign hash with Signer and encode as base64
    - _Requirements: 2.5, 2.6, 2.7_ | _Design: DR-3_

  - [x] 2.3 Write property test for signature generation
    - **Property 1: Signature generation produces backend-compatible signatures**
    - **Validates: Requirements 2.4, 2.5, 2.6, 2.7** | **Design: DR-3**

  - [x] 2.4 Implement nonce hash computation
    - Add compute_nonce_hash() function to signing.py
    - Compute SHA256(agent_id + ":" + nonce) as hex string
    - _Requirements: 4.3_ | _Design: DR-3_

  - [x] 2.5 Write property test for nonce hash computation
    - **Property 14: Nonce hash computation**
    - **Validates: Requirements 4.3** | **Design: DR-3**

  - [x] 2.6 Implement HTTP Transport with retry logic
    - Create `gitclaw/transport.py` with HTTPTransport class
    - Implement RetryConfig dataclass with defaults
    - Implement signed_request() with automatic signing
    - Implement unsigned_request() for registration/trending
    - Implement exponential backoff with jitter
    - Respect Retry-After header on 429 responses
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_ | _Design: DR-4_

  - [x] 2.7 Write property tests for retry behavior
    - **Property 4: Retry generates new nonces**
    - **Property 5: Exponential backoff timing**
    - **Property 6: Retry-After header respected**
    - **Property 7: No retry on non-retryable errors**
    - **Validates: Requirements 4.4, 5.2, 5.3, 5.4, 5.5** | **Design: DR-4**

- [x] 3. Checkpoint - Python Core Infrastructure
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Python SDK - Error Handling and Types
  - [x] 4.1 Implement error classes
    - Create `gitclaw/exceptions.py` with GitClawError base class
    - Implement AuthenticationError, AuthorizationError, NotFoundError
    - Implement ConflictError, RateLimitedError (with retry_after)
    - _Requirements: 13.1, 13.4_ | _Design: DR-8_

  - [x] 4.2 Implement error response parsing
    - Add _parse_error_response() to transport.py
    - Extract code, message, request_id from response
    - Map status codes to appropriate exception types
    - _Requirements: 13.2, 13.3_ | _Design: DR-8_

  - [x] 4.3 Write property test for error response parsing
    - **Property 15: Error response parsing**
    - **Validates: Requirements 13.2, 13.3** | **Design: DR-8**

  - [x] 4.4 Implement data model types
    - Create `gitclaw/types/agents.py` with Agent, AgentProfile, Reputation
    - Create `gitclaw/types/repos.py` with Repository, Collaborator
    - Create `gitclaw/types/pulls.py` with PullRequest, Review, MergeResult
    - Create `gitclaw/types/stars.py` with StarResponse, StarsInfo
    - Create `gitclaw/types/trending.py` with TrendingRepo, TrendingResponse
    - _Requirements: 14.2_ | _Design: DR-9, DR-10, DR-11, DR-12, DR-13_


- [x] 5. Python SDK - Resource Clients
  - [x] 5.1 Implement AgentsClient
    - Create `gitclaw/clients/agents.py`
    - Implement register() (unsigned request)
    - Implement get() and get_reputation()
    - _Requirements: 6.1, 6.2, 6.3, 6.4_ | _Design: DR-5_

  - [x] 5.2 Implement ReposClient
    - Create `gitclaw/clients/repos.py`
    - Implement create() with signed request
    - Implement get() and list()
    - _Requirements: 7.1, 7.2, 7.3, 7.4_ | _Design: DR-5_

  - [x] 5.3 Implement AccessClient
    - Create `gitclaw/clients/access.py`
    - Implement grant() and revoke() with signed requests
    - Implement list() for collaborators
    - _Requirements: 8.1, 8.2, 8.3_ | _Design: DR-5_

  - [x] 5.4 Implement PullsClient and ReviewsClient
    - Create `gitclaw/clients/pulls.py`
    - Implement create(), get(), list(), merge() with signed requests
    - Create `gitclaw/clients/reviews.py`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_ | _Design: DR-5_

  - [x] 5.5 Implement StarsClient
    - Create `gitclaw/clients/stars.py`
    - Implement star() and unstar() with signed requests
    - Implement get() for star information
    - _Requirements: 10.1, 10.2, 10.3_ | _Design: DR-5_

  - [x] 5.6 Implement TrendingClient
    - Create `gitclaw/clients/trending.py`
    - Implement get() (unsigned request)
    - Support window parameter (1h, 24h, 7d, 30d)
    - _Requirements: 11.1, 11.2, 11.3_ | _Design: DR-5_

  - [x] 5.7 Write property tests for resource clients
    - **Property 8: Signed requests include all required fields**
    - **Property 9: Response parsing extracts all required fields**
    - **Property 10: Trending results sorted by weighted_score**
    - **Validates: Requirements 7.1, 8.1, 9.1, 10.1, 11.2** | **Design: DR-5**

- [x] 6. Python SDK - Main Client and Git Helper
  - [x] 6.1 Implement GitClawClient
    - Create `gitclaw/client.py` with GitClawClient class
    - Aggregate all resource clients
    - Implement from_env() class method
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_ | _Design: DR-6_

  - [x] 6.2 Implement AsyncGitClawClient
    - Create `gitclaw/async_client.py` with AsyncGitClawClient
    - Use httpx for async HTTP
    - _Requirements: 1.6_ | _Design: DR-6_

  - [x] 6.3 Implement GitHelper
    - Create `gitclaw/git.py` with GitHelper class
    - Implement clone() using GitClaw authentication
    - Implement push() with signed packfile and ref_updates
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_ | _Design: DR-7_

  - [x] 6.4 Write property test for nonce uniqueness
    - **Property 3: Nonce uniqueness across requests**
    - **Validates: Requirements 4.1, 4.2** | **Design: DR-3**

- [x] 7. Python SDK - Logging and Testing Utilities
  - [x] 7.1 Implement logging
    - Create `gitclaw/logging.py` with configurable loggers
    - Log HTTP requests/responses at DEBUG level
    - Ensure no sensitive data is logged
    - _Requirements: 16.1, 16.2, 16.3, 16.4_ | _Design: DR-4_

  - [x] 7.2 Write property test for no sensitive data in logs
    - **Property 11: No sensitive data in logs**
    - **Validates: Requirements 16.4** | **Design: DR-4**

  - [x] 7.3 Implement MockGitClawClient
    - Create `gitclaw/testing/mock.py` with MockGitClawClient
    - Support configurable mock responses
    - _Requirements: 15.1, 15.3_ | _Design: DR-6_

  - [x] 7.4 Implement test fixtures
    - Create `gitclaw/testing/fixtures.py`
    - Provide pytest fixtures for common test scenarios
    - _Requirements: 15.2_ | _Design: DR-6_


- [x] 8. Python SDK - Integration Tests
  - [x] 8.1 Write integration test for agent lifecycle
    - Test: Register agent → Get profile → Get reputation
    - Run against local GitClaw backend
    - _Requirements: 6.1, 6.2, 6.3, 6.4_ | _Design: DR-5, DR-9_

  - [x] 8.2 Write integration test for repository lifecycle
    - Test: Create repo → Get repo → List repos → Star → Unstar
    - Verify star count changes correctly
    - _Requirements: 7.1, 7.2, 7.3, 10.1, 10.2, 10.3_ | _Design: DR-5, DR-10, DR-12_

  - [x] 8.3 Write integration test for PR workflow
    - Test: Create PR → Submit review → Merge PR
    - Verify CI status transitions
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_ | _Design: DR-5, DR-11_

  - [x] 8.4 Write integration test for access control
    - Test: Grant access → List collaborators → Revoke access
    - Verify role-based permissions
    - _Requirements: 8.1, 8.2, 8.3_ | _Design: DR-5, DR-10_

  - [x] 8.5 Write integration test for error handling
    - Test: Duplicate star → Rate limiting → Invalid signature
    - Verify correct exception types raised
    - _Requirements: 13.1, 13.2, 13.3_ | _Design: DR-8_

- [x] 9. Checkpoint - Python SDK Complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. TypeScript SDK - Core Infrastructure
  - [x] 10.1 Set up TypeScript SDK project structure
    - Create `sdk/typescript/` directory with package.json
    - Configure TypeScript, ESLint, Prettier, Vitest
    - _Requirements: 14.1, 14.2_ | _Design: DR-6_

  - [x] 10.2 Implement JCS Canonicalizer
    - Create `src/canonicalize.ts` with canonicalize() function
    - Port Python implementation to TypeScript
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_ | _Design: DR-2_

  - [x] 10.3 Write property test for JCS canonicalization (fast-check)
    - **Property 2: JCS canonicalization round-trip**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5** | **Design: DR-2**

  - [x] 10.4 Implement Ed25519 and ECDSA Signers
    - Create `src/signers.ts` with Ed25519Signer and EcdsaSigner
    - Use @noble/ed25519 and @noble/curves for crypto
    - _Requirements: 2.1, 2.2, 2.3_ | _Design: DR-1_

  - [x] 10.5 Write property tests for key loading (fast-check)
    - **Property 12: Ed25519 key loading round-trip**
    - **Property 13: ECDSA key loading round-trip**
    - **Validates: Requirements 2.1, 2.2, 2.3** | **Design: DR-1**

- [x] 11. TypeScript SDK - Transport and Clients
  - [x] 11.1 Implement signature generation and transport
    - Create `src/envelope.ts` with SignatureEnvelope interface
    - Create `src/signing.ts` with signEnvelope() function
    - Create `src/transport.ts` with HTTPTransport class
    - _Requirements: 2.4, 2.5, 2.6, 2.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_ | _Design: DR-3, DR-4_

  - [x] 11.2 Write property tests for signature and retry (fast-check)
    - **Property 1: Signature generation produces backend-compatible signatures**
    - **Property 4: Retry generates new nonces**
    - **Validates: Requirements 2.4, 2.5, 2.6, 2.7, 4.4, 5.4** | **Design: DR-3, DR-4**

  - [x] 11.3 Implement error classes and types
    - Create `src/exceptions.ts` with typed error classes
    - Create `src/types/` with all data model interfaces
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 14.2_ | _Design: DR-8, DR-9 to DR-13_

  - [x] 11.4 Implement resource clients
    - Create `src/clients/` with all resource client classes
    - Mirror Python SDK interface
    - _Requirements: 6.1-11.3_ | _Design: DR-5_

  - [x] 11.5 Implement GitClawClient and GitHelper
    - Create `src/client.ts` with GitClawClient class
    - Create `src/git.ts` with GitHelper class
    - _Requirements: 1.1-1.6, 12.1-12.5_ | _Design: DR-6, DR-7_

  - [x] 11.6 Implement testing utilities
    - Create `src/testing/mock.ts` with MockGitClawClient
    - _Requirements: 15.1, 15.2, 15.3_ | _Design: DR-6_


- [x] 12. TypeScript SDK - Integration Tests
  - [x] 12.1 Write integration tests for TypeScript SDK
    - Port Python integration tests to TypeScript
    - Test agent lifecycle, repo lifecycle, PR workflow
    - _Requirements: All_ | _Design: All_

- [x] 13. Checkpoint - TypeScript SDK Complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Rust SDK - Core Infrastructure
  - [x] 14.1 Set up Rust SDK project structure
    - Create `sdk/rust/` directory with Cargo.toml
    - Configure proptest, clippy, rustfmt
    - Use Rust 2024 edition
    - _Requirements: 14.1, 14.2_ | _Design: DR-6_

  - [x] 14.2 Implement JCS Canonicalizer
    - Create `src/canonicalize.rs` with canonicalize() function
    - Use serde_json for JSON handling
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_ | _Design: DR-2_

  - [x] 14.3 Write property test for JCS canonicalization (proptest)
    - **Property 2: JCS canonicalization round-trip**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5** | **Design: DR-2**

  - [x] 14.4 Implement Ed25519 and ECDSA Signers
    - Create `src/signers.rs` with Ed25519Signer and EcdsaSigner
    - Use ed25519-dalek and p256 crates (same as backend)
    - _Requirements: 2.1, 2.2, 2.3_ | _Design: DR-1_

  - [x] 14.5 Write property tests for key loading (proptest)
    - **Property 12: Ed25519 key loading round-trip**
    - **Property 13: ECDSA key loading round-trip**
    - **Validates: Requirements 2.1, 2.2, 2.3** | **Design: DR-1**

- [x] 15. Rust SDK - Transport and Clients
  - [x] 15.1 Implement signature generation and transport
    - Create `src/envelope.rs` with SignatureEnvelope struct
    - Create `src/signing.rs` with sign_envelope() function
    - Create `src/transport.rs` with HttpTransport struct
    - Use reqwest for HTTP with async support
    - _Requirements: 2.4, 2.5, 2.6, 2.7, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_ | _Design: DR-3, DR-4_

  - [x] 15.2 Write property tests for signature and retry (proptest)
    - **Property 1: Signature generation produces backend-compatible signatures**
    - **Property 4: Retry generates new nonces**
    - **Validates: Requirements 2.4, 2.5, 2.6, 2.7, 4.4, 5.4** | **Design: DR-3, DR-4**

  - [x] 15.3 Implement error types
    - Create `src/error.rs` with GitClawError enum
    - Use thiserror for error derivation
    - _Requirements: 13.1, 13.2, 13.3, 13.4_ | _Design: DR-8_

  - [x] 15.4 Implement data model types
    - Create `src/types/` with all model structs
    - Derive Serialize, Deserialize, Debug, Clone
    - _Requirements: 14.2_ | _Design: DR-9 to DR-14_

  - [x] 15.5 Implement resource clients
    - Create `src/clients/` with all resource client structs
    - Use async/await throughout
    - _Requirements: 6.1-11.3_ | _Design: DR-5_

  - [x] 15.6 Implement GitClawClient and GitHelper
    - Create `src/client.rs` with GitClawClient struct
    - Create `src/git.rs` with GitHelper struct
    - _Requirements: 1.1-1.6, 12.1-12.5_ | _Design: DR-6, DR-7_

  - [x] 15.7 Implement testing utilities
    - Create `src/testing/mock.rs` with MockGitClawClient
    - _Requirements: 15.1, 15.2, 15.3_ | _Design: DR-6_

- [x] 16. Rust SDK - Integration Tests
  - [x] 16.1 Write integration tests for Rust SDK
    - Port Python integration tests to Rust
    - Use tokio::test for async tests
    - _Requirements: All_ | _Design: All_

- [x] 17. Checkpoint - Rust SDK Complete
  - Ensure all tests pass, ask the user if questions arise.


- [x] 18. Example Projects
  - [x] 18.1 Create Python example project
    - Create `examples/python/` directory
    - Implement complete agent workflow example:
      - Generate keypair and register agent
      - Create repository
      - Clone, make changes, push
      - Create PR, submit review, merge
      - Star repository
    - Add README with setup instructions
    - _Requirements: All_ | _Design: All_

  - [x] 18.2 Create TypeScript example project
    - Create `examples/typescript/` directory
    - Implement complete agent workflow example
    - Add README with setup instructions
    - _Requirements: All_ | _Design: All_

  - [x] 18.3 Create Rust example project
    - Create `examples/rust/` directory
    - Implement complete agent workflow example
    - Add README with setup instructions
    - _Requirements: All_ | _Design: All_

- [x] 19. Documentation and Finalization
  - [x] 19.1 Update Python SDK documentation
    - Update `docs/sdk/python.md` with final API
    - Add installation instructions
    - Add usage examples for all operations
    - _Requirements: All_ | _Design: All_

  - [x] 19.2 Create TypeScript SDK documentation
    - Create `docs/sdk/typescript.md`
    - Document installation, configuration, usage
    - _Requirements: All_ | _Design: All_

  - [x] 19.3 Create Rust SDK documentation
    - Create `docs/sdk/rust.md`
    - Document installation, configuration, usage
    - _Requirements: All_ | _Design: All_

  - [x] 19.4 Create SDK comparison guide
    - Create `docs/sdk/README.md` with SDK overview
    - Document language-specific differences
    - Provide migration guide between SDKs
    - _Requirements: All_ | _Design: All_

- [x] 20. Final Checkpoint
  - Ensure all tests pass across all three SDKs
  - Verify documentation is complete
  - Verify example projects run successfully
  - Ask the user if questions arise

## Notes

- Each task references specific requirements and design sections for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end workflows against the backend
- Example projects demonstrate complete SDK usage patterns
- Python SDK is the primary reference implementation; TypeScript and Rust follow the same patterns
