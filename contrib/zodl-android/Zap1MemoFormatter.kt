package co.electriccoin.zcash.ui.common.util

/**
 * Parses ZAP1 and legacy NSM1 attestation memos into structured data.
 * See https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md
 */
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

    private val LABELS = mapOf(
        "01" to "Participant enrolled",
        "02" to "Ownership verified",
        "03" to "Contract anchored",
        "04" to "Machine activated",
        "05" to "Hosting paid",
        "06" to "Shield renewed",
        "07" to "Ownership transferred",
        "08" to "Participant exited",
        "09" to "Merkle root anchored",
        "0a" to "Stake deposited",
        "0b" to "Stake withdrawn",
        "0c" to "Reward recorded",
        "0d" to "Proposal submitted",
        "0e" to "Vote cast",
        "0f" to "Result recorded"
    )

    fun parse(memo: String): Attestation? {
        val m = PATTERN.matchEntire(memo.trim().replace("\u0000", "")) ?: return null
        val typeHex = m.groupValues[2].lowercase()
        return Attestation(
            prefix = m.groupValues[1],
            typeHex = typeHex,
            event = EVENTS[typeHex] ?: "TYPE_0x$typeHex",
            label = LABELS[typeHex] ?: "Attestation event",
            hash = m.groupValues[3]
        )
    }

    fun format(memo: String): String? {
        val att = parse(memo) ?: return null
        return "${att.prefix}: ${att.event}  ${att.shortHash}"
    }

    data class Attestation(
        val prefix: String,
        val typeHex: String,
        val event: String,
        val label: String,
        val hash: String
    ) {
        val verifyUrl get() = "https://api.frontiercompute.cash/verify/$hash"
        val shortHash get() = hash.take(12) + "..."
        val isLegacy get() = prefix == "NSM1"
    }
}
