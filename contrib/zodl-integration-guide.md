# Zodl and CrossPay integration proposal

Status: unmerged proposal

This is a backend integration sketch. It is not shipped in Zodl or CrossPay.
The Android [pull request](https://github.com/zodl-inc/zodl-android/pull/2173)
and iOS [pull request](https://github.com/zodl-inc/zodl-ios/pull/1680) closed
unmerged on 2026-07-29. The iOS
[issue](https://github.com/zodl-inc/zodl-ios/issues/1670) remained open at the
2026-08-13 cutoff. None of these receipts proves adoption, review approval, or
production use.

## Security boundary

Never ship a ZAP1 write key in Android, iOS, browser, or other client code. A
write key authorizes event creation. Keep it in the CrossPay backend, use a
dedicated restricted key, and rotate it if exposed.

Do not send raw wallet addresses, destination addresses, intent payloads, or
other personal data to ZAP1. The API stores the strings it receives. The
backend must derive domain-separated pseudonymous fields before submission and
must retain any preimages under its own disclosure policy.

## Proposed backend call

After the backend has independently confirmed a successful swap, it may record
a `TRANSFER` claim:

```http
POST /event
Authorization: Bearer <backend-only-key>
Content-Type: application/json

{
  "event_type": "TRANSFER",
  "wallet_hash": "<domain-separated-source-commitment>",
  "new_wallet_hash": "<domain-separated-destination-commitment>",
  "serial_number": "<domain-separated-intent-commitment>"
}
```

The active construction is:

```text
BLAKE2b_32(
  0x07 ||
  len(old_wallet) || old_wallet ||
  len(new_wallet) || new_wallet ||
  len(serial_number) || serial_number
)
```

All lengths are two-byte big-endian values. The leaf hash uses the
`NordicShield_` personalization.

## What the receipt means

The returned leaf hash identifies an operator-issued claim. Once a covering
root exists, the proof path can show inclusion under that supplied root. This
does not prove that a swap happened, that the fields are complete, or that the
operator recorded every attempt. A recorded txid establishes transaction
existence only. Encrypted memo binding requires separate disclosure material.

Failed swaps should not be encoded as successful `TRANSFER` events. A distinct
failure event is not assigned in the active registry.

## Local references

- [Protocol](../ONCHAIN_PROTOCOL.md)
- [OpenAPI](../conformance/openapi.yaml)
- [Android parser draft](zodl-android/Zap1MemoFormatter.kt)
- [iOS parser draft](zodl-ios/Zap1MemoParser.swift)
