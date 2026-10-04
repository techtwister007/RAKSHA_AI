package com.example.noharness;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The target's own regression suite — benign behaviour only. It must pass unchanged before and
 * after the RAKSHA fix, which is exactly what the gate's DIFFERENTIAL_CORPUS own-tests check reads:
 * an honest length-prefixed record is parsed identically whether or not the index is clamped.
 */
class ParserTest {

    @Test
    void parsesAnHonestRecord() {
        // header says 2 elements, two bytes follow — checksum of 'a' and 'b'
        assertEquals('a' + 'b', Parser.parse(new byte[] {0x02, 'a', 'b'}));
    }

    @Test
    void emptyInputIsZero() {
        assertEquals(0, Parser.parse(new byte[] {}));
    }

    @Test
    void zeroCountReadsNothing() {
        assertEquals(0, Parser.parse(new byte[] {0x00, 'x', 'y'}));
    }
}
