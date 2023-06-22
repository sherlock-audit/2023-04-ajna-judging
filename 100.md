lemonmon

high

# Loss of unclaimed rewards if a bucket went bankrupt

## Summary

When the `PositionManager.memorializePositions` function is called by a lender, they can potentially lose their unclaimed rewards in the case where a bucket went bankrupt.

## Vulnerability Detail

When a lender is calling the function `PositionManager.memorializePositions`, the protocol checks for previous deposits:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/PositionManager.sol#L232

Then, if there are previous deposits, the protocol checks whether the bucket went bankrupt and zeros out the previous tracked LP:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/PositionManager.sol#L234-L236

So when calling `PositionManager.memorializePositions`, the lender can potentially lose his unclaimed rewards, because claiming rewards relies on the tracked LP, which got zeroed out by `PositionManager.memorializePositions` (line 234-236) if the bucket went bankrupt.

The `RewardsManager.claimRewards`, which is used to claim the rewards, and it's subsequent called functions like `RewardsManager._calculateAndClaimAllRewards`, do not check whether the bucket is bankrupt:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L120-L144

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L510-L546

## Impact

Lenders can lose unclaimed rewards.

## Code Snippet

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/PositionManager.sol#L232

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/PositionManager.sol#L234-L236

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L120-L144

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L510-L546

## Tool used

Manual Review

## Recommendation

Either:

Don't zero out the tracked LPs when a bucket went bankrupt inside the `PositionManager.memorializePositions` function (line 234-236).

Or:

Check whether a bucket went bankrupt when `RewardsManager.claimRewards` is called and don't pay any rewards in that case.
