hyh

medium

# Limit index isn't checked in repayDebt, so user control is void

## Summary

repayDebt() resulting LUP `_revertIfPriceDroppedBelowLimit()` check is not performed in the case of pure debt repayment without collateral pulling.

## Vulnerability Detail

LUP will move (up or no change) as a result of debt repayment and repayDebt() have `limitIndex_` argument. As a part of multi-position strategy a user might not be satisfied with repay results if LUP has increased not substantially enough.

I.e. there is a user control argument, it is detrimental from UX perspective to request, but not use it, as for any reason a borrower might want to control for that move: they might expect the final level to be somewhere, as an example for the sake of other loans of that borrower.

## Impact

Unfavorable repayDebt() operations will be executed and the borrowers, whose strategies were dependent on the realized LUP move, can suffer a loss.

Probability of execution is high (no prerequisites, current ordinary behavior), while the probability of the following loss is medium, so placing the severity to be medium.

## Code Snippet

There is a `limitIndex_` parameter in repayDebt():

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/ERC20Pool.sol#L208-L232

```solidity
    function repayDebt(
        address borrowerAddress_,
        uint256 maxQuoteTokenAmountToRepay_,
        uint256 collateralAmountToPull_,
        address collateralReceiver_,
>>      uint256 limitIndex_
    ) external nonReentrant {
        ...

        RepayDebtResult memory result = BorrowerActions.repayDebt(
            auctions,
            buckets,
            deposits,
            loans,
            poolState,
            borrowerAddress_,
            maxQuoteTokenAmountToRepay_,
            collateralAmountToPull_,
>>          limitIndex_
        );
```

Currently `_revertIfPriceDroppedBelowLimit()` is done on collateral pulling only:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/BorrowerActions.sol#L365-L375

```solidity
        if (vars.pull) {
            // only intended recipient can pull collateral
            if (borrowerAddress_ != msg.sender) revert BorrowerNotSender();

            // an auctioned borrower in not allowed to pull collateral (even if collateralized at the new LUP) if auction is not settled
            if (result_.inAuction) revert AuctionActive();

            // calculate LUP only if it wasn't calculated in repay action
            if (!vars.repay) result_.newLup = Deposits.getLup(deposits_, result_.poolDebt);

>>          _revertIfPriceDroppedBelowLimit(result_.newLup, limitIndex_);
```

## Tool used

Manual Review

## Recommendation

Consider adding the same check in the repayment part:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/BorrowerActions.sol#L328

```diff
            result_.newLup = Deposits.getLup(deposits_, result_.poolDebt);
+           _revertIfPriceDroppedBelowLimit(result_.newLup, limitIndex_);
```

If no repay or pull it looks ok to skip the check to save gas.