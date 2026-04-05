// ZAP1 Memo Conformance - Swift runner
// Run: swift run-swift.swift
//
// Loads test-vectors.json and runs each vector against the
// Zap1Attestation parser logic.  Reports PASS/FAIL per vector.

import Foundation

// Inline the parser so this script is self-contained.
// Direct copy of Zap1MemoParser.swift logic.
// If the real file diverges, the test is stale and must be updated.
struct Zap1Attestation {
    let prefix: String
    let typeHex: String
    let event: String
    let hash: String

    var shortHash: String { String(hash.prefix(12)) + "..." }
    var isLegacy: Bool { prefix == "NSM1" }

    private static let events: [String: String] = [
        "01": "PROGRAM_ENTRY", "02": "OWNERSHIP_ATTEST",
        "03": "CONTRACT_ANCHOR", "04": "DEPLOYMENT",
        "05": "HOSTING_PAYMENT", "06": "SHIELD_RENEWAL",
        "07": "TRANSFER", "08": "EXIT",
        "09": "MERKLE_ROOT", "0a": "STAKING_DEPOSIT",
        "0b": "STAKING_WITHDRAW", "0c": "STAKING_REWARD",
        "0d": "GOVERNANCE_PROPOSAL", "0e": "GOVERNANCE_VOTE",
        "0f": "GOVERNANCE_RESULT"
    ]

    private static let pattern = try! NSRegularExpression(
        pattern: #"^(ZAP1|NSM1):([0-9a-fA-F]{2}):([0-9a-fA-F]{64})$"#
    )

    static func parse(_ memo: String) -> Zap1Attestation? {
        let trimmed = memo.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\0", with: "")
        let range = NSRange(trimmed.startIndex..., in: trimmed)
        guard let match = pattern.firstMatch(in: trimmed, range: range),
              let prefixRange = Range(match.range(at: 1), in: trimmed),
              let typeRange = Range(match.range(at: 2), in: trimmed),
              let hashRange = Range(match.range(at: 3), in: trimmed)
        else { return nil }

        let prefix = String(trimmed[prefixRange])
        let typeHex = String(trimmed[typeRange]).lowercased()
        let hash = String(trimmed[hashRange])

        return Zap1Attestation(
            prefix: prefix,
            typeHex: typeHex,
            event: events[typeHex] ?? "TYPE_0x\(typeHex)",
            hash: hash
        )
    }
}

// Load and parse test vectors
func loadVectors() -> [[String: Any]] {
    let paths = [
        "test-vectors.json",
        "contrib/zodl-conformance/test-vectors.json"
    ]

    var data: Data? = nil
    for p in paths {
        let url = URL(fileURLWithPath: p)
        if let d = try? Data(contentsOf: url) {
            data = d
            break
        }
    }

    guard let fileData = data else {
        fputs("ERROR: test-vectors.json not found\n", stderr)
        fputs("Run from the zodl-conformance directory or the repo root\n", stderr)
        exit(1)
    }

    guard let json = try? JSONSerialization.jsonObject(with: fileData) as? [String: Any],
          let vectors = json["vectors"] as? [[String: Any]] else {
        fputs("ERROR: failed to parse test-vectors.json\n", stderr)
        exit(1)
    }

    return vectors
}

// Run tests
let vectors = loadVectors()
var passed = 0
var failed = 0

print("ZAP1 Conformance - Swift")
print("Vectors: \(vectors.count)")
print("")

for v in vectors {
    let id = v["id"] as! String
    let input = v["input"] as! String
    let expectParse = v["expected_parse"] as! Bool
    let desc = v["description"] as! String

    let result = Zap1Attestation.parse(input)
    var errors: [String] = []

    if expectParse {
        guard let r = result else {
            errors.append("expected parse success, got nil")
            print("  FAIL  \(id) - \(desc)")
            for e in errors { print("        \(e)") }
            failed += 1
            continue
        }

        if let expPrefix = v["expected_prefix"] as? String, r.prefix != expPrefix {
            errors.append("prefix: got '\(r.prefix)', want '\(expPrefix)'")
        }
        if let expType = v["expected_type_hex"] as? String, r.typeHex != expType {
            errors.append("typeHex: got '\(r.typeHex)', want '\(expType)'")
        }
        if let expEvent = v["expected_event_name"] as? String, r.event != expEvent {
            errors.append("event: got '\(r.event)', want '\(expEvent)'")
        }
        if let expHash = v["expected_hash"] as? String, r.hash != expHash {
            errors.append("hash: got '\(r.hash)', want '\(expHash)'")
        }
        if let expShort = v["expected_short_hash"] as? String, r.shortHash != expShort {
            errors.append("shortHash: got '\(r.shortHash)', want '\(expShort)'")
        }
        if let expLegacy = v["expected_is_legacy"] as? Bool, r.isLegacy != expLegacy {
            errors.append("isLegacy: got '\(r.isLegacy)', want '\(expLegacy)'")
        }
    } else {
        if result != nil {
            errors.append("expected parse failure, got result: \(result!.event)")
        }
    }

    if errors.isEmpty {
        print("  PASS  \(id)")
        passed += 1
    } else {
        print("  FAIL  \(id) - \(desc)")
        for e in errors { print("        \(e)") }
        failed += 1
    }
}

print("")
print("Results: \(passed) passed, \(failed) failed, \(passed + failed) total")

if failed > 0 {
    exit(1)
}
