package com.example.svc;

/**
 * The service entry point a request reaches. Splits a request line "actor|action" and hands
 * the action to the audit logger. This is the function the fuzz harness drives, and the one
 * whose stack frame appears above the Jazzer sanitizer frame when the bug fires.
 */
public class RequestHandler {

    private final AuditLogger audit = new AuditLogger();

    public String handle(String request) {
        String actor = "anonymous";
        String action = request;
        int sep = request.indexOf('|');
        if (sep >= 0) {
            actor = request.substring(0, sep);
            action = request.substring(sep + 1);
        }
        return audit.write(actor, action);
    }
}
