// schema/IProofOracle.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IProofOracle — RFC Draft Interface for On-Chain Agentic Attestations
 * @author Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
 * @notice STATUS: RFC DRAFT / PROPOSAL (not yet deployed on mainnet).
 *         Defines an on-chain verifier interface for EIP-712 / ECDSA secp256k1 bridged
 *         attestations derived from off-chain PROOF-VC v2 (Ed25519) certificates.
 *         Note: Symmetric HMAC-SHA256 is intentionally NOT used on-chain because EVM
 *         storage and calldata are public; only asymmetric signatures are valid here.
 */
interface IProofOracle {
    struct Attestation {
        bytes32 domainHash;       // keccak256(abi.encodePacked(normalizedDomain))
        uint8 score;              // Deterministic PROOF score (0..100)
        bool injectionFree;       // DOM prompt-injection & steganography guard result
        bytes32 claimRoot;        // SHA-256 Merkle root of canonical SourcedFact claims
        uint64 issuedAt;          // Unix timestamp (seconds)
        uint64 expiresAt;         // Bounded expiration timestamp (seconds)
        bytes signature;          // EIP-712 ECDSA signature from rootSigner (65 bytes)
    }

    event AttestationVerified(bytes32 indexed domainHash, uint8 score, bytes32 claimRoot, uint64 expiresAt);

    function verifyAttestation(Attestation calldata attestation) external view returns (bool isValid);
    function getRootAuthority() external view returns (address rootSigner);
}
