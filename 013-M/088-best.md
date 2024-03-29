hyh

medium

# LenderActions's moveQuoteToken can create a total debt undercoverage

## Summary

moveQuoteToken() doesn't ensure that pool debt is less than deposits after operation, while unutilized deposit fee can reduce total deposits as a result of the move.

## Vulnerability Detail

Unutilized deposit fee can create a `poolState_.debt > Deposits.treeSum(deposits_)` state, which isn't controlled for in moveQuoteToken().

## Impact

Pool can enter technical corner case when LUP is actually lower than HTP, numerically it will not be the case due to bounded nature of LUP calculation.

This breaks the core logic of the pool with the corresponding material miscalculations, but has low probability, so setting the severity to be medium.

## Code Snippet

moveQuoteToken() can reduce overall deposits due to unutilized deposit fee incurred:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/LenderActions.sol#L285-L289

```solidity
        lup_ = Deposits.getLup(deposits_, poolState_.debt);
        // apply unutilized deposit fee if quote token is moved from above the LUP to below the LUP
        if (vars.fromBucketPrice >= lup_ && vars.toBucketPrice < lup_) {
            movedAmount_ = Maths.wmul(movedAmount_, Maths.WAD - _depositFeeRate(poolState_.rate));
        }
```

But `debt < deposits` state aren't controlled for:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/LenderActions.sol#L311-L312

```solidity
        // check loan book's htp against new lup, revert if move drives LUP below HTP
        if (params_.fromIndex < params_.toIndex && vars.htp > lup_) revert LUPBelowHTP();
```

As it's done in removeQuoteToken(), where it is `LUP < HTP || poolState_.debt > Deposits.treeSum(deposits_)`:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/LenderActions.sol#L413-L425

```solidity
        lup_ = Deposits.getLup(deposits_, poolState_.debt);

        uint256 htp = Maths.wmul(params_.thresholdPrice, poolState_.inflator);

        if (
            // check loan book's htp doesn't exceed new lup
            htp > lup_
            ||
            // ensure that pool debt < deposits after removal
            // this can happen if lup and htp are less than min bucket price and htp > lup (since LUP is capped at min bucket price)
            (poolState_.debt != 0 && poolState_.debt > Deposits.treeSum(deposits_))
        ) revert LUPBelowHTP();

```

LUP is being bounded by deposits tree, i.e. the calculation assumes that total debt (the amount whose index is being located) is lower than total deposits (the tree where it is being located):

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/internal/Deposits.sol#L411-L422

```solidity
    /**
     *  @notice Returns `LUP` for a given debt value (capped at min bucket price).
     *  @param  deposits_ Deposits state struct.
     *  @param  debt_     The debt amount to calculate `LUP` for.
     *  @return `LUP` for given debt.
     */
    function getLup(
        DepositsState storage deposits_,
        uint256 debt_
    ) internal view returns (uint256) {
        return _priceAt(findIndexOfSum(deposits_, debt_));
    }
```

## Tool used

Manual Review

## Recommendation

Consider adding the `(poolState_.debt != 0 && poolState_.debt > Deposits.treeSum(deposits_))` logic to moveQuoteToken():

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/LenderActions.sol#L311-L312

```diff
        // check loan book's htp against new lup, revert if move drives LUP below HTP
-       if (params_.fromIndex < params_.toIndex && vars.htp > lup_) revert LUPBelowHTP();
+       if (params_.fromIndex < params_.toIndex && (vars.htp > lup_ || (poolState_.debt != 0 && poolState_.debt > Deposits.treeSum(deposits_))) revert LUPBelowHTP();
```

The same approach can be added to HTP check in the kickWithDeposit() case.