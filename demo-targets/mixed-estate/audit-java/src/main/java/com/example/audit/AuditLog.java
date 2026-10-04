package com.example.audit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Writes one audit line per gateway request. The request header is logged verbatim. */
public final class AuditLog {
    private static final Logger LOG = LogManager.getLogger(AuditLog.class);

    public static void record(String userAgent) {
        LOG.info("gateway request from {}", userAgent);
    }
}
