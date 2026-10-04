#!/usr/bin/env sh
# One-time Maven warm-up for the Java demo target. Run ONCE with network, then never again:
# the gate runs Maven offline (-o), so every artifact it will ever ask for must already be in
# ~/.m2 — the vulnerable log4j (2.14.1), the fixed one the dependency bump resolves to (2.17.1),
# JUnit, the Jazzer API, and the compiler/surefire/dependency plugins.
#
#   ./deploy/warm-maven.sh            (from the repository root)
set -eu

cd "$(dirname "$0")/../demo-targets/java-log4shell"

echo "warming the vulnerable build (log4j 2.14.1) ..."
mvn -q -B test-compile dependency:build-classpath -Dmdep.outputFile=/dev/null -Dmdep.includeScope=test
mvn -q -B test -DskipTests=false >/dev/null 2>&1 || true   # fetches surefire; the test may fail here by design

echo "warming the patched build (log4j 2.17.1) ..."
mvn -q -B test-compile dependency:build-classpath -Dmdep.outputFile=/dev/null -Dmdep.includeScope=test -Dlog4j.version=2.17.1

rm -rf target
echo "done. Maven can now run offline: both log4j versions, JUnit, Jazzer API and plugins are cached."
