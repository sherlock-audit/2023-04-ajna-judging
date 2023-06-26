stopthecap

high

# Staking rewards can be sandwichable

## Summary
Staking rewards can be sandwiched because there is no fee or lockup period on stakin/unstaking

## Vulnerability Detail
There exists no fee or lock-up period associated to staking to receive a portion of the rewards which if a an attacker can profit from by sandwiching they staking and unstaking and profit from the updated exchange rate on the bucket and the  epoch: 
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L196

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L153

## Impact
Attacker can profit from staking and unstaking a tokenId in the same block because there is no fee or lockup period to prevent it

## Code Snippet
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L153

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/RewardsManager.sol#L770

## Tool used

Manual Review

## Recommendation
Consider implementing a staking and unstaking fee or a "warm up" period where stakers can't accrue rewards