# ZAP1 public record, 2026-08-13

This is a bounded evidence index for the ZAP1 Q3 retrogrant application. The [machine-readable digest index](public-records-20260813.json) contains every response locator, observation time, byte count, full SHA-256 digest, claim boundary, and reopen trigger.

The pack does not reproduce the frozen HTTP response bodies, so an external reviewer needs the exact historical bytes to recompute the recorded digests. Fresh reads can test current state, but cannot recreate a changed historical response. Treat this as a digest index, not a self-contained public archive. It does not make mutable facts permanently current.

## Controlling record

- [Application issue 31](https://github.com/Financial-Privacy-Foundation/ZcashCoinholderGrantsProgram/issues/31) was open and labeled `Ready For Vote - All Steps Completed` at `2026-08-13T23:36:23.0285081Z`. Issue-body SHA-256: `c46d5387bfd3a5518acdda3a54d56b7b4fdb9334efe0371fda9bf397919109f3`. This proves administrative state only, not an award, endorsement, likely outcome, or payment.

- The [administrator eligibility comment](https://github.com/Financial-Privacy-Foundation/ZcashCoinholderGrantsProgram/issues/31#issuecomment-4435296484) says that posting on the forum and sharing the link makes the application officially eligible for the vote. Body SHA-256: `943e522e09f79836cd9d953bf08bbc2eda3f3885b4d1de61cc933007f842ad9e`. Eligibility is not selection.

- The [A4 funding clarification](https://github.com/Financial-Privacy-Foundation/ZcashCoinholderGrantsProgram/issues/31#issuecomment-5170813827) is applicant-authored, 994 UTF-8 bytes, SHA-256 `02ddbf9fb6de170bb8e99c7327da865d09173538c5abdd95a27732d24b3eda02`. It is the exact application-record statement, not independent validation of every funding fact.

- The [forum project update](https://forum.zcashcommunity.com/t/retroactive-grant-application-zap1-attestation-protocol-and-verification-tooling/55664/3) is post `252646`, version `1`, with a 350-byte raw body and SHA-256 `4e15fd60ab223f658393367ab2e1f8b651628a898bfa61b3ce923a8c6d3e3e3c`. It refers to the project and contains no funding or payment clarification.

- The [ZCG public disbursement page](https://openzcash.org/zcg/disbursements) contained the exact `@Zk-nd3r` row `Security bounty`, `Security Bounty`, dated `2026-06-26`, for `2,000,000` USD cents and `4,848,000,000` ZEC zatoshis. The page response SHA-256 was `5fb2163c6bbf4e6cd102daf126cafe29c7365815117a8fa4d51bb4379e6e78e4` at `2026-08-13T23:36:23.0285081Z`. This is a separate security bounty, not ZAP1 funding. Page-scoped absence checks found neither literal `4.77` nor `477000000`; that does not prove absence from every payment source.

## Daira and ZIP boundaries

- [Daira's NU7 post 22](https://forum.zcashcommunity.com/t/nu7-coinholder-vote/56912/22) is a governance, terminology, Sprout-risk, and NSM-question critique for the NU7 consensus poll. Its raw-body SHA-256 is `c07b4cb8fb269bfcc8afd1249cd6485c9034e8455e821e868a281c71986f9225`. It is not a ZAP1 review or retrogrant ruling. [Josh Swihart's post 7](https://forum.zcashcommunity.com/t/nu7-coinholder-vote/56912/7) explicitly distinguishes consensus sentiment polling from the coinholder vote and process used for retroactive grants.

- [Daira's direct ZIP 1243 review comment](https://github.com/zcash/zips/pull/1243#discussion_r3028252127) identifies a Zcash terminology collision. Comment-body SHA-256: `6832c37b36baf545d6909d9cdb493a3530578b3017d9a377a9767eed5f79a86c`. The current head names the field `label`, which is consistent with incorporating the comment. The review state was `COMMENTED`, not approved.

- [ZIP pull request 1243](https://github.com/zcash/zips/pull/1243) was open, draft, and unmerged at head `0537ce5606e1e1700b1278285cdceef8ffbd8397` when read at `2026-08-13T23:34:45.1233925Z`. The applicant's [self-review](https://github.com/zcash/zips/pull/1243#issuecomment-5123710072), body SHA-256 `21fb60ad347012c3c2c8c36d4b3bcef7bf039865ee95604afda67ba3eda6b20c`, records unresolved wire-format and registry divergence. Do not claim ZIP assignment, acceptance, merge, one coherent standard wire profile, or adoption.

## Zooko boundary

A bounded search at `2026-08-13T23:36:45.4522004Z` returned zero results for the exact GitHub query `ZAP1 commenter:zooko`. The three-post ZAP1 forum topic contained only applicant posts, and the captured like lists did not contain Zooko. The complete query and forum-response hashes are in the JSON receipt.

This is limited negative evidence. It does not prove absence across the internet, private channels, aliases, or future activity. Do not claim or imply Zooko endorsement. `Zooko proof` means applying a privacy and honest-claims discipline, not borrowing a person's name as validation.

## Cash and non-authorizations

For the ZAP1 retrogrant, booked cash is `$0` and hard receivable is `$0`.

This record authorizes no commit, push, deploy, publication, wallet action, provider transmission, vote solicitation, award claim, endorsement claim, or payout-probability claim. Fresh primary reads control any later present-tense statement.
