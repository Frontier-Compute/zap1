# ZAP1 Crosslink integration sketch

Status: experimental, no consensus integration

The write API accepts `STAKING_DEPOSIT`, `STAKING_WITHDRAW`, and
`STAKING_REWARD`. These events record what the ZAP1 operator submitted. They do
not query or validate Crosslink state.

Example operator claim:

```json
POST /event
{
  "event_type": "STAKING_DEPOSIT",
  "wallet_hash": "validator-subject-commitment",
  "amount_zat": 100000000,
  "validator_id": "validator-001"
}
```

The exact leaf is:

```text
BLAKE2b_32(
  0x0A ||
  len(wallet_hash) || wallet_hash ||
  amount_zat_be_u64 ||
  len(validator_id) || validator_id
)
```

The withdrawal shape changes only the type byte to `0x0B`. The reward shape
uses type `0x0C`, the length-prefixed wallet field, an eight-byte amount, and a
four-byte epoch.

A proof can establish inclusion of the submitted claim under a supplied root.
It cannot establish that stake moved, a reward was earned, the event stream is
complete, or the operator is a validator. Any production integration must bind
these fields to a finalized consensus source and publish that verifier policy.
