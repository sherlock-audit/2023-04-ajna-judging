ctf_sec

high

# User can claim reward more than once

## Summary
user can claim reward more than once
## Vulnerability Detail
in RewardsManager.sol
```solidity 
function claimRewards(
        uint256 tokenId_,
        uint256 epochToClaim_,
        uint256 minAmount_
    ) external override {
        StakeInfo storage stakeInfo = stakes[tokenId_];

        if (msg.sender != stakeInfo.owner) revert NotOwnerOfDeposit();

        if (isEpochClaimed[tokenId_][epochToClaim_]) revert AlreadyClaimed();

        uint256 rewardsEarned = _calculateAndClaimAllRewards(
            stakeInfo,
            tokenId_,
            epochToClaim_,
            true,
            stakeInfo.ajnaPool
        );

        // transfer rewards to claimer, ensuring amount is not below specified min amount
        _transferAjnaRewards({
            transferAmount_: rewardsEarned,
            minAmount_:      minAmount_
        });
    }
``` 
the snippet of code above is a claim function that allows users to claim their rewards.
in the claim function there is a check.
```solidity
if (isEpochClaimed[tokenId_][epochToClaim_]) revert AlreadyClaimed();
```
this if statement is meant to not allow claiming of rewards from the same epoch more than once. However, this check can be easily passed.
in RewardsManager.sol
```solidity
  function updateBucketExchangeRatesAndClaim(
        address pool_,
        bytes32 subsetHash_,
        uint256[] calldata indexes_
    ) external override returns (uint256 updateReward) {
        // revert if trying to update exchange rates for a non Ajna pool
        if (!positionManager.isAjnaPool(pool_, subsetHash_)) revert NotAjnaPool();

        updateReward = _updateBucketExchangeRates(pool_, indexes_);

        // transfer bucket update rewards to sender even if there's not enough balance for entire amount
        _transferAjnaRewards({
            transferAmount_: updateReward,
            minAmount_:      0
        });
    }
```
the function above is an alternative way to claim rewards. The problem here is that this function does not check if a user has already claimed their reward for an epoch. Because of this, a malicious user can claim his reward more than once.

the function is calling [_updateBucketExchangeRates(pool_, indexes_)](https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L618)

then calling

```solidity
// calculate rewards earned for updating bucket exchange rate
  updatedRewards_ += _updateBucketExchangeRateAndCalculateRewards(
      pool_,
      indexes_[i],
      curBurnEpoch,
      totalBurnedInEpoch,
      totalInterestEarned
);
```

calling _updateBucketExchangeRateAndCalculateRewards, and calculate the reward

https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L749

```solidity
// calculate rewards earned for updating bucket exchange rate 
  rewards_ = interestEarned_ == 0 ? 0 : Maths.wdiv(
      Maths.wmul(
          UPDATE_CLAIM_REWARD,
          Maths.wmul(
              burnFactor,
              curBucketExchangeRate - prevBucketExchangeRate
          )
      ),
      Maths.wmul(curBucketExchangeRate, interestEarned_)
  );
```

there is no check:

```solidity
if (isEpochClaimed[tokenId_][epochToClaim_]) revert AlreadyClaimed();
```

when calling updateBucketExchangeRatesAndClaim, then user can claim the reward twice by calling updateBucketExchangeRatesAndClaim and claim reward

## Impact
a malicious user can claim reward more than once, this is a loss of funds for the protocol. 

## Code Snippet

https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L129

https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L246

https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L749

## Tool used

Manual Review

## Recommendation
add a check to see if rewards have already been claimed in `updateBucketExchangeRatesAndClaim`