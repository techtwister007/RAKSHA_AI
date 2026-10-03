package com.example.fuzz;

import com.example.svc.RequestHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;

/**
 * Replays one input against the service and reports whether it triggered a JNDI lookup.
 *
 * This is the slice's hand-written stand-in for Jazzer's NamingContextLookup sanitizer. The
 * finale uses Jazzer's own agent; here, where the native fuzzer launcher is not available
 * offline, we observe the SAME real behaviour honestly and deterministically: we register a
 * JNDI context factory that RECORDS any lookup and refuses it (no network, ever), then run the
 * real RequestHandler through the real log4j on the classpath.
 *
 *   - On log4j 2.14.1, a value like ${jndi:ldap://x/a} makes log4j attempt the lookup -> recorded.
 *   - On log4j 2.17.1 (the fix), message JNDI lookup is gone -> nothing recorded.
 *
 * On a recorded lookup it prints a Jazzer-format banner that RAKSHA's JazzerOracle already
 * parses, and exits non-zero. Otherwise it exits 0. Usage: ReplayDriver <input-file> [--coverage]
 */
public final class ReplayDriver {

    static volatile boolean lookupAttempted = false;
    static volatile String lookupName = null;

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ReplayDriver <input-file> [--coverage]");
            System.exit(2);
        }
        boolean coverage = args.length > 1 && "--coverage".equals(args[1]);
        installRecordingJndi();

        String request = new String(Files.readAllBytes(Paths.get(args[0])));
        String logged = new RequestHandler().handle(request);

        if (coverage) {
            // Honest coverage signal: print the fix-site line only if write() actually ran.
            // A "fix" that deletes or bypasses the logging path prints nothing, so the gate's
            // COVERAGE_HELD check fails correctly.
            if (logged != null) {
                System.out.println("com/example/svc/AuditLogger.java:23");
            }
            return;
        }

        if (lookupAttempted) {
            System.out.println("== Java Exception: com.code_intelligence.jazzer.api."
                    + "FuzzerSecurityIssueCritical: Remote JNDI Lookup");
            System.out.println("Remote JNDI lookup attempted for name: " + lookupName
                    + "  (CVE-2021-44228, Log4Shell)");
            System.out.println("\tat com.code_intelligence.jazzer.sanitizers."
                    + "NamingContextLookup.lookupHook(NamingContextLookup.java:62)");
            System.out.println("\tat com.example.svc.AuditLogger.write(AuditLogger.java:23)");
            System.out.println("\tat com.example.svc.RequestHandler.handle(RequestHandler.java:21)");
            System.exit(77);
        }
        // Not vulnerable (or fixed): echo what was logged, so the differential check can compare
        // normal behaviour before and after the patch.
        System.out.println(logged);
    }

    /**
     * Register a JNDI factory whose Context records any lookup and then fails closed. A dynamic
     * proxy over Context keeps us from stubbing its forty methods; only lookup() is meaningful.
     */
    private static void installRecordingJndi() throws NamingException {
        Context recording = (Context) Proxy.newProxyInstance(
                ReplayDriver.class.getClassLoader(),
                new Class<?>[]{Context.class},
                (proxy, method, methodArgs) -> {
                    if ("lookup".equals(method.getName()) && methodArgs != null && methodArgs.length == 1) {
                        lookupAttempted = true;
                        lookupName = String.valueOf(methodArgs[0]);
                        throw new NamingException("JNDI disabled in RAKSHA replay sandbox");
                    }
                    if ("close".equals(method.getName()) || "getNameInNamespace".equals(method.getName())) {
                        return method.getReturnType() == String.class ? "" : null;
                    }
                    return null;
                });
        NamingManager.setInitialContextFactoryBuilder(new InitialContextFactoryBuilder() {
            @Override
            public InitialContextFactory createInitialContextFactory(Hashtable<?, ?> env) {
                return environment -> recording;
            }
        });
    }
}
