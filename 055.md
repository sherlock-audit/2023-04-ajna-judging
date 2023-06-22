0xeix

medium

# Pool collateral can be incorrectly calculated if collateralReceiver == address(this) in ERC20Pool.sol

## Summary

When the user calls repayDebt() function, he can specify address(this) as the collateralReceiver

## Vulnerability Detail

In ERC20Pool.sol, there is repayDebt() function with borrowerAddress and collateralReceiver parameters that are user-facing. Therefore user can specify address(this) as collateralReceiver and disrupt pool calculations regarding pool.collateral as they are implemented before the actual collateral transfer

## Impact

Medium as pool collateral will be calculated incorrectly and with wrong actual amount

## Code Snippet

collateralReceiver parameter:
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/ERC20Pool.sol#L212

transfer of collateral:
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/ERC20Pool.sol#L270
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/ERC20Pool.sol#L497

change of state:
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/ERC20Pool.sol#L240
https://github.com/sherlock-audit/2023-04-ajna/blob/main/ajna-core/src/libraries/external/BorrowerActions.sol#L387

## Tool used

Manual Review

## Recommendation

Implement additional logic to prevent user from putting address(this) parameter as collateralReceiver