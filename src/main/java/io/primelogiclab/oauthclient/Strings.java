package io.primelogiclab.oauthclient;

import java.util.regex.Pattern;

/** Small string helpers shared by the configuration classes. */
final class Strings {

    /** Control and format characters, which could fake or split log lines. */
    private static final Pattern UNSAFE_CHARS = Pattern.compile("[\\p{Cc}\\p{Cf}\\u2028\\u2029]");

    private Strings() {
    }

    static boolean isBlank(String v) {
        return v == null || v.trim().isEmpty();
    }

    /** Trimmed value, or {@code null} when blank. */
    static String trim(String v) {
        return isBlank(v) ? null : v.trim();
    }

    /** Value safe to put in a log line or exception message: control characters replaced by '?'. */
    static String safe(String s) {
        return s == null ? null : UNSAFE_CHARS.matcher(s).replaceAll("?");
    }
}
