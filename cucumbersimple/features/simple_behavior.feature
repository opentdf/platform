Feature: Account Maintenance

Scenario: New account
Given I have a new account
 Then the account balance must be 0.00 USD

Scenario: Deposit money into account
Given I have an account with 0.00 USD
 When I deposit 5.00 USD
 Then the account balance must be 5.00 USD

Scenario: Withdraw money from account
Given I have an account with 11.00 USD
 When I withdraw 5.00 USD
 Then the account balance must be 6.00 USD

Scenario: Attempt to overdraw account
Given I have an account with 11.00 USD
 When I try to withdraw 50.00 USD
 Then the transaction should error
