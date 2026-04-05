// ZAP1 Memo Conformance - Kotlin runner
// Run: kotlinc -script run-kotlin.kts
//
// This loads test-vectors.json and runs each vector against
// the Zap1MemoFormatter parser logic.  Reports PASS/FAIL per vector.

import java.io.File

// Inline the parser so this script is self-contained.
// This is a direct copy of Zap1MemoFormatter.kt logic.
// If the real file diverges from this, the test is stale and must be updated.
object Zap1MemoFormatter {
    private val PATTERN = Regex("^(ZAP1|NSM1):([0-9a-fA-F]{2}):([0-9a-fA-F]{64})$")

    private val EVENTS = mapOf(
        "01" to "PROGRAM_ENTRY",
        "02" to "OWNERSHIP_ATTEST",
        "03" to "CONTRACT_ANCHOR",
        "04" to "DEPLOYMENT",
        "05" to "HOSTING_PAYMENT",
        "06" to "SHIELD_RENEWAL",
        "07" to "TRANSFER",
        "08" to "EXIT",
        "09" to "MERKLE_ROOT",
        "0a" to "STAKING_DEPOSIT",
        "0b" to "STAKING_WITHDRAW",
        "0c" to "STAKING_REWARD",
        "0d" to "GOVERNANCE_PROPOSAL",
        "0e" to "GOVERNANCE_VOTE",
        "0f" to "GOVERNANCE_RESULT"
    )

    fun parse(memo: String): Attestation? {
        val m = PATTERN.matchEntire(memo.trim().replace("\u0000", "")) ?: return null
        val typeHex = m.groupValues[2].lowercase()
        return Attestation(
            prefix = m.groupValues[1],
            typeHex = typeHex,
            event = EVENTS[typeHex] ?: "TYPE_0x$typeHex",
            hash = m.groupValues[3]
        )
    }

    data class Attestation(
        val prefix: String,
        val typeHex: String,
        val event: String,
        val hash: String
    ) {
        val shortHash get() = hash.take(12) + "..."
        val isLegacy get() = prefix == "NSM1"
    }
}

// Minimal JSON parser - no dependencies needed.
// Handles the flat structure of each test vector.
fun parseVectors(json: String): List<Map<String, Any?>> {
    val vectors = mutableListOf<Map<String, Any?>>()
    // Find the "vectors" array
    val arrStart = json.indexOf("\"vectors\"")
    if (arrStart == -1) error("No vectors array found")
    val bracketStart = json.indexOf('[', arrStart)
    var depth = 0
    var i = bracketStart
    var objStart = -1
    while (i < json.length) {
        when (json[i]) {
            '[' -> depth++
            ']' -> { depth--; if (depth == 0) break }
            '{' -> { if (depth == 1) objStart = i }
            '}' -> {
                if (depth == 1 && objStart != -1) {
                    vectors.add(parseObject(json.substring(objStart, i + 1)))
                    objStart = -1
                }
            }
        }
        i++
    }
    return vectors
}

fun parseObject(obj: String): Map<String, Any?> {
    val map = mutableMapOf<String, Any?>()
    val keyPattern = Regex("\"(\\w+)\"\\s*:\\s*")
    var pos = 0
    while (pos < obj.length) {
        val keyMatch = keyPattern.find(obj, pos) ?: break
        val key = keyMatch.groupValues[1]
        var valStart = keyMatch.range.last + 1
        while (valStart < obj.length && obj[valStart] == ' ') valStart++
        if (valStart >= obj.length) break

        val value: Any?
        when {
            obj[valStart] == '"' -> {
                // String value - handle escapes
                val sb = StringBuilder()
                var j = valStart + 1
                while (j < obj.length) {
                    if (obj[j] == '\\' && j + 1 < obj.length) {
                        when (obj[j + 1]) {
                            '"' -> { sb.append('"'); j += 2 }
                            '\\' -> { sb.append('\\'); j += 2 }
                            'n' -> { sb.append('\n'); j += 2 }
                            'u' -> {
                                val hex = obj.substring(j + 2, j + 6)
                                sb.append(hex.toInt(16).toChar())
                                j += 6
                            }
                            else -> { sb.append(obj[j + 1]); j += 2 }
                        }
                    } else if (obj[j] == '"') {
                        break
                    } else {
                        sb.append(obj[j])
                        j++
                    }
                }
                value = sb.toString()
                pos = j + 1
            }
            obj.substring(valStart).startsWith("true") -> {
                value = true
                pos = valStart + 4
            }
            obj.substring(valStart).startsWith("false") -> {
                value = false
                pos = valStart + 5
            }
            obj.substring(valStart).startsWith("null") -> {
                value = null
                pos = valStart + 4
            }
            else -> {
                // Number or something else - skip to next comma/brace
                val end = obj.indexOfAny(charArrayOf(',', '}'), valStart)
                value = obj.substring(valStart, if (end == -1) obj.length else end).trim()
                pos = if (end == -1) obj.length else end
            }
        }
        map[key] = value
        if (pos < obj.length && (obj[pos] == ',' || obj[pos] == ' ')) pos++
    }
    return map
}

// Run tests
val scriptDir = File(if (args.isNotEmpty()) args[0] else ".")
    .let { if (it.isDirectory) it else File(".") }
val vectorFile = File(scriptDir, "test-vectors.json")
    .let { if (it.exists()) it else File("contrib/zodl-conformance/test-vectors.json") }
    .let { if (it.exists()) it else File("test-vectors.json") }

if (!vectorFile.exists()) {
    System.err.println("ERROR: test-vectors.json not found")
    System.err.println("Run from the zodl-conformance directory or pass the directory as arg")
    kotlin.system.exitProcess(1)
}

val json = vectorFile.readText()
val vectors = parseVectors(json)

var pass = 0
var fail = 0

println("ZAP1 Conformance - Kotlin")
println("Vectors: ${vectors.size}")
println()

for (v in vectors) {
    val id = v["id"] as String
    val input = v["input"] as String
    val expectParse = v["expected_parse"] as Boolean
    val desc = v["description"] as String

    val result = Zap1MemoFormatter.parse(input)
    val errors = mutableListOf<String>()

    if (expectParse) {
        if (result == null) {
            errors.add("expected parse success, got null")
        } else {
            val expPrefix = v["expected_prefix"] as String?
            val expType = v["expected_type_hex"] as String?
            val expEvent = v["expected_event_name"] as String?
            val expHash = v["expected_hash"] as String?
            val expShort = v["expected_short_hash"] as String?
            val expLegacy = v["expected_is_legacy"] as Boolean?

            if (expPrefix != null && result.prefix != expPrefix)
                errors.add("prefix: got '${result.prefix}', want '$expPrefix'")
            if (expType != null && result.typeHex != expType)
                errors.add("typeHex: got '${result.typeHex}', want '$expType'")
            if (expEvent != null && result.event != expEvent)
                errors.add("event: got '${result.event}', want '$expEvent'")
            if (expHash != null && result.hash != expHash)
                errors.add("hash: got '${result.hash}', want '$expHash'")
            if (expShort != null && result.shortHash != expShort)
                errors.add("shortHash: got '${result.shortHash}', want '$expShort'")
            if (expLegacy != null && result.isLegacy != expLegacy)
                errors.add("isLegacy: got '${result.isLegacy}', want '$expLegacy'")
        }
    } else {
        if (result != null) {
            errors.add("expected parse failure, got result: ${result.event}")
        }
    }

    if (errors.isEmpty()) {
        println("  PASS  $id")
        pass++
    } else {
        println("  FAIL  $id - $desc")
        for (e in errors) println("        $e")
        fail++
    }
}

println()
println("Results: $pass passed, $fail failed, ${pass + fail} total")

if (fail > 0) {
    kotlin.system.exitProcess(1)
}
