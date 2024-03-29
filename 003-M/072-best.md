branch_indigo

medium

# Lenders lose interests and pay deposit fees due to no slippage control

## Summary
When a lender deposits quote tokens below the minimum of LUP(Lowest Utilization Price) and HTP(Highest Threshold Price), the deposits will not earn interest and will also be charged deposit fees, according to [docs](https://www.ajna.finance/pdf/Ajna%20Protocol%20Whitepaper_03-24-2023.pdf). When a lender deposits to a bucket, they are vulnerable to pool LUP slippage which might cause them to lose funds due to fee charges against their will. 
## Vulnerability Detail


A lender would call `addQuoteToken()` to deposit. This function only allows entering expiration time for transaction settlement, but there is no slippage protection. 
```solidity
//Pool.sol
    function addQuoteToken(
        uint256 amount_,
        uint256 index_,
        uint256 expiry_
    ) external override nonReentrant returns (uint256 bucketLP_) {
        _revertAfterExpiry(expiry_);
        PoolState memory poolState = _accruePoolInterest();
        // round to token precision
        amount_ = _roundToScale(amount_, poolState.quoteTokenScale);
        uint256 newLup;
        (bucketLP_, newLup) = LenderActions.addQuoteToken(
            buckets,
            deposits,
            poolState,
            AddQuoteParams({
                amount: amount_,
                index:  index_
            })
        );
       ...
```
In LenderActions.sol, `addQuoteToken()` takes current `DepositsState` in storage and current `poolState_.debt` in storage to calculate spot LUP prior to deposit. And this LUP is compared with user input bucket `index_` to determine if the lender will be punished with deposit fees. The deposit amount is then written to storage. 
```solidity
//LenderActions.sol
    function addQuoteToken(
        mapping(uint256 => Bucket) storage buckets_,
        DepositsState storage deposits_,
        PoolState calldata poolState_,
        AddQuoteParams calldata params_
    ) external returns (uint256 bucketLP_, uint256 lup_) {
  ...
          // charge unutilized deposit fee where appropriate
 |>       uint256 lupIndex = Deposits.findIndexOfSum(deposits_, poolState_.debt);
        bool depositBelowLup = lupIndex != 0 && params_.index > lupIndex;
        if (depositBelowLup) {
            addedAmount = Maths.wmul(addedAmount, Maths.WAD - _depositFeeRate(poolState_.rate));
        }
...
   Deposits.unscaledAdd(deposits_, params_.index, unscaledAmount);
...
```
It should be noted that current `deposits_` and `poolState_.debt` can be different from when the user invoked the transaction, which will result in a different LUP spot price unforeseen by the lender to determine deposit fees. Even though lenders can input a reasonable expiration time `expirty_`, this will only prevent stale transactions to be executed and not offer any slippage control. 

When there are many lenders depositing around the same time, LUP spot price can be increased and if the user transaction settles after a whale lender which moves the LUP spot price up significantly, the user might get accidentally punished for depositing below LUP. Or there could also be malicious lenders trying to ensure their transactions settle at a favorable LUP/HTP and front-run the user transaction, in which case the user transaction might still settle after the malicious lender and potentially get charged for fees.

## Impact
Lenders might get charged deposit fees due to slippage against their will with or without MEV attacks, lenders might also lose on interest by depositing below HTP. 

## Code Snippet
[https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/base/Pool.sol#L146-L150](https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/base/Pool.sol#L146-L150)

[https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/libraries/external/LenderActions.sol](https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/libraries/external/LenderActions.sol#L173)

[https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/libraries/external/LenderActions.sol#L195](https://github.com/ajna-finance/ajna-core/blob/e3632f6d0b196fb1bf1e59c05fb85daf357f2386/src/libraries/external/LenderActions.sol#L195)
## Tool used

Manual Review

## Recommendation
Add slippage protection in Pool.sol `addQuoteToken()`. A lender can enable slippage protection, which will enable comparing deposit `index_` with `lupIndex` in LenderActions.sol.