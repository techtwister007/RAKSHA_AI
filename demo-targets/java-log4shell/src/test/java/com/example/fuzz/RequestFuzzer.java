package com.example.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.example.svc.RequestHandler;

/**
 * The Jazzer fuzz harness. It is three lines of real logic: take the fuzzer's bytes as a
 * string and hand them to the service. We write no detection code — Jazzer's built-in
 * NamingContextLookup sanitizer raises FuzzerSecurityIssueCritical ("Remote JNDI Lookup")
 * the moment the vulnerable log4j interprets a ${jndi:...} value. This is why Java is the
 * easiest target: the harness is trivial and the oracle ships with the fuzzer.
 *
 * Run (Jazzer standalone):
 *   jazzer --cp=&lt;classpath&gt; --target_class=com.example.fuzz.RequestFuzzer
 */
public class RequestFuzzer {

    private static final RequestHandler HANDLER = new RequestHandler();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        HANDLER.handle(data.consumeRemainingAsString());
    }
}
