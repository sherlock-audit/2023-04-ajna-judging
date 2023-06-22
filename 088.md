hyh

high

# moveQuoteToken updates pool state using intermediary LUP, biasing pool's interest rate calculations

## Summary

In LenderActions's moveQuoteToken() LUP is being evaluated after liquidity removal, but before liquidity addition. This intermediary LUP doesn't correspond to the final state of the pool, but is returned as if it does, leading to a bias in pool target utilization and interest rate calculations.

## Vulnerability Detail

moveQuoteToken() calculates LUP after deposit removal only instead of doing so after the whole operation, being atomic removal from one index and addition to another, and then updates the pool accounting `_updateInterestState(poolState, newLup)` with this intermediary `newLup`, that doesn't correspond to the final state of the pool.

## Impact

moveQuoteToken() is one of the base frequently used operations, so the state of the pool will be frequently enough updated with incorrect LUP and `EMA of LUP * t0 debt` internal accounting variable be systematically biased, which leads to incorrect interest rate dynamics of the pool.

There is no low-probability prerequisites and the impact is a bias in interest rate calculations, so setting the severity to be high.

## Code Snippet

moveQuoteToken() calculates the LUP right after the deposit removal:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/LenderActions.sol#L237-L312

```solidity
    function moveQuoteToken(
        mapping(uint256 => Bucket) storage buckets_,
        DepositsState storage deposits_,
        PoolState calldata poolState_,
        MoveQuoteParams calldata params_
>>  ) external returns (uint256 fromBucketRedeemedLP_, uint256 toBucketLP_, uint256 movedAmount_, uint256 lup_) {
        ...

>>      (movedAmount_, fromBucketRedeemedLP_, vars.fromBucketRemainingDeposit) = _removeMaxDeposit(
            deposits_,
            RemoveDepositParams({
                depositConstraint: params_.maxAmountToMove,
                lpConstraint:      vars.fromBucketLenderLP,
                bucketLP:          vars.fromBucketLP,
                bucketCollateral:  vars.fromBucketCollateral,
                price:             vars.fromBucketPrice,
                index:             params_.fromIndex,
                dustLimit:         poolState_.quoteTokenScale
            })
        );

>>      lup_ = Deposits.getLup(deposits_, poolState_.debt);
        // apply unutilized deposit fee if quote token is moved from above the LUP to below the LUP
        if (vars.fromBucketPrice >= lup_ && vars.toBucketPrice < lup_) {
            movedAmount_ = Maths.wmul(movedAmount_, Maths.WAD - _depositFeeRate(poolState_.rate));
        }

        vars.toBucketUnscaledDeposit = Deposits.unscaledValueAt(deposits_, params_.toIndex);
        vars.toBucketScale           = Deposits.scale(deposits_, params_.toIndex);
        vars.toBucketDeposit         = Maths.wmul(vars.toBucketUnscaledDeposit, vars.toBucketScale);

        toBucketLP_ = Buckets.quoteTokensToLP(
            toBucket.collateral,
            toBucket.lps,
            vars.toBucketDeposit,
            movedAmount_,
            vars.toBucketPrice,
            Math.Rounding.Down
        );

        // revert if (due to rounding) the awarded LP in to bucket is 0
        if (toBucketLP_ == 0) revert InsufficientLP();

>>      Deposits.unscaledAdd(deposits_, params_.toIndex, Maths.wdiv(movedAmount_, vars.toBucketScale));

        vars.htp = Maths.wmul(params_.thresholdPrice, poolState_.inflator);

        // check loan book's htp against new lup, revert if move drives LUP below HTP
        if (params_.fromIndex < params_.toIndex && vars.htp > lup_) revert LUPBelowHTP();
```

Intermediary LUP is then being used for interest rate state update:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/Pool.sol#L176-L207

```solidity
    function moveQuoteToken(
        uint256 maxAmount_,
        uint256 fromIndex_,
        uint256 toIndex_,
        uint256 expiry_
    ) external override nonReentrant returns (uint256 fromBucketLP_, uint256 toBucketLP_, uint256 movedAmount_) {
        _revertAfterExpiry(expiry_);
        PoolState memory poolState = _accruePoolInterest();

        _revertIfAuctionDebtLocked(deposits, poolState.t0DebtInAuction, fromIndex_, poolState.inflator);

        uint256 newLup;
        (
            fromBucketLP_,
            toBucketLP_,
            movedAmount_,
>>          newLup
        ) = LenderActions.moveQuoteToken(
            buckets,
            deposits,
            poolState,
            MoveQuoteParams({
                maxAmountToMove: maxAmount_,
                fromIndex:       fromIndex_,
                toIndex:         toIndex_,
                thresholdPrice:  Loans.getMax(loans).thresholdPrice
            })
        );

        // update pool interest rate state
>>      _updateInterestState(poolState, newLup);
    }
```

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/Pool.sol#L675-L680

```solidity
    function _updateInterestState(
        PoolState memory poolState_,
        uint256 lup_
    ) internal {

>>      PoolCommons.updateInterestState(interestState, emaState, deposits, poolState_, lup_);
```

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/PoolCommons.sol#L148-L152

```solidity
                // calculate the EMA of LUP * t0 debt
                vars.lupt0DebtEma = uint256(
                    PRBMathSD59x18.mul(vars.weightTu, int256(vars.lupt0DebtEma)) +
                    PRBMathSD59x18.mul(1e18 - vars.weightTu, int256(interestParams_.lupt0Debt))
                );
```

This will lead to a bias in target utilization and interest rate dynamics:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/PoolCommons.sol#L269-L289

```solidity
    function _calculateInterestRate(
        PoolState memory poolState_,
        uint256 debtEma_,
        uint256 depositEma_,
        uint256 debtColEma_,
        uint256 lupt0DebtEma_
    ) internal pure returns (uint256 newInterestRate_)  {
        // meaningful actual utilization
        int256 mau;
        // meaningful actual utilization * 1.02
        int256 mau102;

        if (poolState_.debt != 0) {
            // calculate meaningful actual utilization for interest rate update
            mau    = int256(_utilization(debtEma_, depositEma_));
            mau102 = mau * PERCENT_102 / 1e18;
        }

        // calculate target utilization
        int256 tu = (lupt0DebtEma_ != 0) ? 
            int256(Maths.wdiv(debtColEma_, lupt0DebtEma_)) : int(Maths.WAD);
```

## Tool used

Manual Review

## Recommendation

Consider calculating LUP in moveQuoteToken() after deposit addition to the destination bucket. Deposit fee can be calculated from initial LUP only, so only one, final, LUP recalculation looks to be necessary.