// schema/eai-contract.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PROOF Oracle Attestation Interface for Autonomous Agentic Commerce
 * @author Arthur Mellin / PROOF X-Ray (https://www.proofxray.com)
 * @notice Validates off-chain HMAC-SHA256 and DNS signatures issued by the PROOF Oracle
 *         to prevent smart contracts & on-chain agents from executing hallucinated pricing.
 */
interface IProofOracle {
    struct Attestation {
        bytes32 domainHash;
        uint256 score;
        bytes32 pricingMatrixHash;
        uint256 timestamp;
        bytes signature;
    }

    event AttestationVerified(bytes32 indexed domainHash, bool isAutonomousCompliant);

    function verifyAttestation(Attestation calldata attestation) external view returns (bool isValid);
    function getRootAuthority() external view returns (address rootSigner);
}
