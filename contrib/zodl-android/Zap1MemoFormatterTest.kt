package co.electriccoin.zcash.ui.common.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test

class Zap1MemoFormatterTest {

    @Test
    fun parseProgramEntry() {
        val att = Zap1MemoFormatter.parse("ZAP1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b")
        assertNotNull(att)
        assertEquals("ZAP1", att!!.prefix)
        assertEquals("01", att.typeHex)
        assertEquals("PROGRAM_ENTRY", att.event)
        assertEquals("Participant enrolled", att.label)
        assertEquals("075b00df2860...", att.shortHash)
        assertFalse(att.isLegacy)
    }

    @Test
    fun parseMerkleRoot() {
        val att = Zap1MemoFormatter.parse("ZAP1:09:024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a")
        assertNotNull(att)
        assertEquals("MERKLE_ROOT", att!!.event)
        assertEquals("Merkle root anchored", att.label)
        assertTrue(att.verifyUrl.startsWith("https://api.frontiercompute.cash/verify/"))
    }

    @Test
    fun parseGovernance() {
        val att = Zap1MemoFormatter.parse("ZAP1:0d:a487c25f5867a9e3760c45ae7eed24d84e771568f1826a889ccd94b3c7c3a5b5")
        assertNotNull(att)
        assertEquals("GOVERNANCE_PROPOSAL", att!!.event)
    }

    @Test
    fun parseLegacyNSM1() {
        val att = Zap1MemoFormatter.parse("NSM1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b")
        assertNotNull(att)
        assertEquals("NSM1", att!!.prefix)
        assertTrue(att.isLegacy)
        assertEquals("PROGRAM_ENTRY", att.event)
    }

    @Test
    fun rejectsInvalidMemos() {
        assertNull(Zap1MemoFormatter.parse("Hello world"))
        assertNull(Zap1MemoFormatter.parse("ZAP1:xx:notahash"))
        assertNull(Zap1MemoFormatter.parse("ZAP1:01:tooshort"))
        assertNull(Zap1MemoFormatter.parse(""))
        assertNull(Zap1MemoFormatter.parse("ZAP2:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"))
    }

    @Test
    fun formatReturnsReadableString() {
        val result = Zap1MemoFormatter.format("ZAP1:04:f265b9a06a61b2b8c6eeed7fc00c7aa686ad511053467815bf1f1037d460e1f1")
        assertNotNull(result)
        assertTrue(result!!.contains("DEPLOYMENT"))
    }

    @Test
    fun formatReturnsNullForNonZap1() {
        assertNull(Zap1MemoFormatter.format("Just a regular memo"))
    }
}
