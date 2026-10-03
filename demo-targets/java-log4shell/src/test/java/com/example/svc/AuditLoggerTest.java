package com.example.svc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The service's own regression suite. It asserts normal behaviour only — the behaviour that
 * must survive the Log4Shell fix (a dependency bump). RAKSHA's gate runs this suite on the
 * patched build as half of the differential check: the bump must not change any of this.
 */
class AuditLoggerTest {

    @Test
    void logsActorAndAction() {
        String line = new AuditLogger().write("alice", "login");
        assertEquals("audit: actor=alice action=login", line);
    }

    @Test
    void handlerSplitsActorFromAction() {
        String line = new RequestHandler().handle("bob|logout");
        assertEquals("audit: actor=bob action=logout", line);
    }

    @Test
    void handlerDefaultsActorWhenNoSeparator() {
        String line = new RequestHandler().handle("ping");
        assertEquals("audit: actor=anonymous action=ping", line);
    }

    @Test
    void ordinaryBraceTextIsLoggedVerbatim() {
        // A value that merely looks structured must still be logged as-is, both before and
        // after the fix. This is the test that would catch a fix that over-sanitises input.
        String line = new RequestHandler().handle("svc|deploy ${version} to prod");
        assertTrue(line.endsWith("action=deploy ${version} to prod"), line);
    }
}
