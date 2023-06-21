ctf_sec

high

# Lose of reward from user very easily

## Summary
An unsuspecting user may lose all his rewards

## Vulnerability Detail
```solidity
   /**
     *  @notice Utility function to transfer `Ajna` rewards to the sender.
     *  @dev    This function is used to transfer rewards to the `msg.sender` after a successful claim or update.
     *  @dev    It is used to ensure that rewards claimers are able to claim portion from remaining tokens if a claim would exceed the remaining contract balance.
     *  @dev    Reverts with `InsufficientLiquidity` if calculated rewards or contract balance is below specified min amount to receive limit.
     *  @param transferAmount_ Amount of rewards earned by the caller.
     *  @param minAmount_      Min amount that rewards claimer wants to recieve.
     */
    function _transferAjnaRewards(uint256 transferAmount_, uint256 minAmount_) internal {
        uint256 ajnaBalance = IERC20(ajnaToken).balanceOf(address(this));

        // cap amount to transfer at available contract balance
        if (transferAmount_ > ajnaBalance) transferAmount_ = ajnaBalance;

        // revert if amount to transfer is lower than limit amount
        if (transferAmount_ < minAmount_) revert InsufficientLiquidity();

        if (transferAmount_ != 0) {
            // transfer amount to rewards claimer
            IERC20(ajnaToken).safeTransfer(msg.sender, transferAmount_);
        }
    }
```
this function is meant to transfer reward tokens, the problem here is that a user can easily lose rewards when there is insufficient balance when calling `_transferAjnaRewards(amount, 0)`
this can happen frequently as `_transferAjnaRewards(amount, 0)` is called by multiple functions. below are snippets where `_transferAjnaRewards(amount, 0)` can be called and therefore lose rewards for the user.

```solidity
function stake(
        uint256 tokenId_
    ) external override {
        address ajnaPool = positionManager.poolKey(tokenId_);

        // check that msg.sender is owner of tokenId
        if (IERC721(address(positionManager)).ownerOf(tokenId_) != msg.sender) revert NotOwnerOfDeposit();

        StakeInfo storage stakeInfo = stakes[tokenId_];
        stakeInfo.owner    = msg.sender;
        stakeInfo.ajnaPool = ajnaPool;

        uint96 curBurnEpoch = uint96(IPool(ajnaPool).currentBurnEpoch());

        // record the staking epoch
        stakeInfo.stakingEpoch = curBurnEpoch;

        // initialize last time interaction at staking epoch
        stakeInfo.lastClaimedEpoch = curBurnEpoch;

        uint256[] memory positionIndexes = positionManager.getPositionIndexes(tokenId_);
        uint256 noOfPositions = positionIndexes.length;
        uint256 bucketId;

        for (uint256 i = 0; i < noOfPositions; ) {
            bucketId = positionIndexes[i];

            BucketState storage bucketState = stakeInfo.snapshot[bucketId];
            // record the number of lps in bucket at the time of staking
            bucketState.lpsAtStakeTime = positionManager.getLP(tokenId_, bucketId);
            // record the bucket exchange rate at the time of staking
            bucketState.rateAtStakeTime = IPool(ajnaPool).bucketExchangeRate(bucketId);

            // iterations are bounded by array length (which is itself bounded), preventing overflow / underflow
            unchecked { ++i; }
        }

        emit Stake(msg.sender, ajnaPool, tokenId_);

        // transfer LP NFT to this contract
        IERC721(address(positionManager)).transferFrom(msg.sender, address(this), tokenId_);

        // calculate rewards for updating exchange rates, if any
        uint256 updateReward = _updateBucketExchangeRates(
            ajnaPool,
            positionIndexes
        );

        // transfer bucket update rewards to sender even if there's not enough balance for entire amount
        _transferAjnaRewards({
            transferAmount_: updateReward,
            minAmount_:      0
        });
    }
```
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
## Impact
If the pool does not have sufficient balance when calling the function `stake`,and `updateBucketExchangeRatesAndClaim`, he will lose his rewards. This is a loss of funds for the user.

## Code Snippet
https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L120
https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L153
https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/RewardsManager.sol#L246

## Tool used

Manual Review

## Recommendation

We recommend the protocol always let user specify minAmount when claim the staking reward, instead of hardcode the minAmount to 0 when calling _transferAjnaRewards