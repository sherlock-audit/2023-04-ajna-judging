stopthecap

high

# `permit` signatures can be replayed if approval is revoked during valid timestamp

## Summary
permit signatures can be replayed if approval is revoked during valid timestamp

## Vulnerability Detail

When using the `permit` function in the `PermitERC721` contract, there is a flaw when a signature can be replayed to steal NFTs from the owner. 

The attack vector opens when an owner (Bob) let's say of NFT id `1` signs a permit for address `0x01`  with whatever deadline that is not `block.timestamp`. If Bob revokes the approval for `0x01`, meanwhile the timestamp still holds:
```@solidity
if (block.timestamp > deadline_) revert PermitExpired();
```

the signature will be able to be replayed by anyone, most likely `0x01` to approve the spending of the token again.

This happens because the `nonce` that they use to generate the `digest` : 

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/PermitERC721.sol#L147

is only updated if the token is actually transferred, enabling to replay the signature if the approval is revoked.

 
## Impact

Steal an NFT from a previous canceled approval

## Code Snippet
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/PermitERC721.sol#L133-L157

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/PermitERC721.sol#L269

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/PermitERC721.sol#L147
## Tool used

Manual Review

## Recommendation
Increment the `nonce` on approvals too, not just on transfers. It should be a new nonce for every call to permit.