package com.example.noharness;

/**
 * A tiny length-prefixed record parser — the no-harness Java demo target.
 *
 * It ships NO fuzz harness and NO RAKSHA driver. The public entry point is an ordinary
 * {@code public static int parse(byte[])}, exactly the shape a real library exposes. RAKSHA's
 * Java deep lane discovers it, synthesizes a driver that feeds it bytes, and finds the defect
 * with no human writing a harness.
 *
 * The defect is ordinary and realistic: the first byte is a caller-supplied element count and
 * the following bytes are the elements, but the count is trusted. A record whose header
 * over-claims its length (count larger than the bytes that follow) walks {@code data} past its
 * end — an unchecked array read, {@link ArrayIndexOutOfBoundsException} (CWE-125).
 *
 *   parse({0x02,'a','b'})        -> 0x61 + 0x62 = 195   (benign: header honest)
 *   parse({0x05,'a','b'})        -> ArrayIndexOutOfBoundsException (header over-claims)
 *
 * The RAKSHA fix (template lane, zero inference) clamps the index to the backing length, so the
 * over-claiming record stops reading past the end while every honest record is byte-identical —
 * which is exactly what the gate's differential + coverage checks prove.
 */
public final class Parser {

    private Parser() {
    }

    public static int parse(byte[] data) {
        if (data.length == 0) {
            return 0;
        }
        int count = data[0] & 0xFF;      // attacker-controlled claimed element count
        int checksum = 0;
        for (int i = 0; i < count; i++) {
            checksum += data[i + 1] & 0xFF;   // unchecked read — OOB when the header over-claims
        }
        return checksum;
    }
}
