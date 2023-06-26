hyh

high

# LUP is not recalculated after adding kicking penalty to pool's debt, so kick() updates the pool state with an outdated LUP

## Summary

_kick() first calculates LUP, then adds kicking penalty, so the LUP returned without recalculation doesn't include the penalty and this way is outdated whenever it is not zero.

## Vulnerability Detail

kick() and kickWithDeposit() (when deposit doesn't have any excess over the needed bond) returns _kick() calculated LUP, which is generally higher then real one being calculated before kicking penalty was added to the total debt.

## Impact

kick() is one of the base frequently used operations, so the state of the pool will be frequently enough updated with incorrect LUP and `EMA of LUP * t0 debt` internal accounting variable be systematically biased, which leads to incorrect interest rate dynamics of the pool.

There is no low-probability prerequisites and the impact is a bias in interest rate calculations, so setting the severity to be high.

## Code Snippet

kick() updates the `poolState` with _kick() returned `result.lup`:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/base/Pool.sol#L277-L313

```solidity
    function kick(
        address borrower_,
        uint256 npLimitIndex_
    ) external override nonReentrant {
        PoolState memory poolState = _accruePoolInterest();

        // kick auction
>>      KickResult memory result = KickerActions.kick(
            auctions,
            deposits,
            loans,
            poolState,
            borrower_,
            npLimitIndex_
        );

        // update in memory pool state struct
        poolState.debt            =  Maths.wmul(result.t0PoolDebt, poolState.inflator);
        poolState.t0Debt          =  result.t0PoolDebt;
        poolState.t0DebtInAuction += result.t0KickedDebt;

        // adjust t0Debt2ToCollateral ratio
        _updateT0Debt2ToCollateral(
            result.debtPreAction,
            0, // debt post kick (for loan in auction) not taken into account
            result.collateralPreAction,
            0  // collateral post kick (for loan in auction) not taken into account
        );

        // update pool balances state
        poolBalances.t0Debt          = poolState.t0Debt;
        poolBalances.t0DebtInAuction = poolState.t0DebtInAuction;
        // update pool interest rate state
>>      _updateInterestState(poolState, result.lup);

        if (result.amountToCoverBond != 0) _transferQuoteTokenFrom(msg.sender, result.amountToCoverBond);
    }
```

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/KickerActions.sol#L115-L134

```solidity
    function kick(
        ...
    ) external returns (
        KickResult memory
    ) {
>>      return _kick(
            auctions_,
            deposits_,
            loans_,
            poolState_,
            borrowerAddress_,
            limitIndex_,
            0
        );
    }
```

In _kick() kicking penalty is added to the total debt of the pool:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/KickerActions.sol#L438-L446

```solidity
        // when loan is kicked, penalty of three months of interest is added
>>      vars.t0KickPenalty = Maths.wdiv(Maths.wmul(kickResult_.t0KickedDebt, poolState_.rate), 4 * 1e18);
        vars.kickPenalty   = Maths.wmul(vars.t0KickPenalty, poolState_.inflator);

>>      kickResult_.t0PoolDebt   = poolState_.t0Debt + vars.t0KickPenalty;
        kickResult_.t0KickedDebt += vars.t0KickPenalty;

        // update borrower debt with kicked debt penalty
        borrower.t0Debt = kickResult_.t0KickedDebt;
```

While the function calculates LUP before that (for _isCollateralized() check) and does not recalculate it after the penalty was added:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/KickerActions.sol#L364-L442

```solidity
    function _kick(
        ...
    ) internal returns (
        KickResult memory kickResult_
    ) {
        ...
        // add amount to remove to pool debt in order to calculate proposed LUP
>>      kickResult_.lup          = Deposits.getLup(deposits_, poolState_.debt + additionalDebt_);

        ...

        // when loan is kicked, penalty of three months of interest is added
        vars.t0KickPenalty = Maths.wdiv(Maths.wmul(kickResult_.t0KickedDebt, poolState_.rate), 4 * 1e18);
        vars.kickPenalty   = Maths.wmul(vars.t0KickPenalty, poolState_.inflator);

>>      kickResult_.t0PoolDebt   = poolState_.t0Debt + vars.t0KickPenalty;
```

kickWithDeposit() returns _kick() calculated `kickResult_.lup` (i.e. before kick penalty) whenever `vars.amountToDebitFromDeposit <= kickResult_.amountToCoverBond`:

https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/KickerActions.sol#L190-L216

```solidity
        // kick top borrower
>>      kickResult_ = _kick(
            auctions_,
            deposits_,
            loans_,
            poolState_,
            Loans.getMax(loans_).borrower,
            limitIndex_,
            vars.amountToDebitFromDeposit
        );

        // amount to remove from deposit covers entire bond amount
        if (vars.amountToDebitFromDeposit > kickResult_.amountToCoverBond) {
            // cap amount to remove from deposit at amount to cover bond
            vars.amountToDebitFromDeposit = kickResult_.amountToCoverBond;

            // recalculate the LUP with the amount to cover bond
            kickResult_.lup = Deposits.getLup(deposits_, poolState_.debt + vars.amountToDebitFromDeposit);
            // entire bond is covered from deposit, no additional amount to be send by lender
            kickResult_.amountToCoverBond = 0;
>>      } else {
            // lender should send additional amount to cover bond
            kickResult_.amountToCoverBond -= vars.amountToDebitFromDeposit;
        }

        // revert if the bucket price used to kick and remove is below new LUP
        if (vars.bucketPrice < kickResult_.lup) revert PriceBelowLUP();
```

## Tool used

Manual Review

## Recommendation

Consider using initial LUP for _isCollateralized() check in _kick() as `additionalDebt_` is zero in plain kick() case, and calculating the final LUP at the end of _kick().

Consider refactoring kickWithDeposit(): for example, calculating the LUP therein with the corresponding `additionalDebt_` after _kick() call, and adding the flag to _kick() call to indicate that LUP calculation isn't needed.