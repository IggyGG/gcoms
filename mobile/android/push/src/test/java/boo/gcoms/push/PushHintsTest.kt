package boo.gcoms.push
import org.junit.Assert.*
import org.junit.Test

class PushHintsTest {
    @Test fun acceptsOnlyGenericOpaqueHint() {
        val data = mapOf("gcoms_activity" to "message", "gcoms_reference" to "a".repeat(64))
        assertEquals("a".repeat(64), PushHints.reference(data))
        assertNull(PushHints.reference(data + ("message" to "must not be forwarded")))
        assertNull(PushHints.reference(data + ("gcoms_reference" to "not-a-reference")))
        assertNull(PushHints.reference(data + ("gcoms_activity" to "file")))
    }
}
