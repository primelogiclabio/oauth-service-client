package io.primelogiclab.oauthclient;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Proves the build runs tests on every JDK in CI; remove once real tests exist. */
class BuildSmokeTest {

    @Test
    void runsOnASupportedJdk() {
        String version = System.getProperty("java.specification.version");
        assertTrue(version.equals("1.8") || Integer.parseInt(version) >= 9, version);
    }
}
