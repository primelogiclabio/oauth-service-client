package io.primelogiclab.oauthclient;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal RFC 8259 JSON reader/writer (copied from oauth-connector), so token responses and JWTs need no JSON library.
 * Objects become {@link LinkedHashMap}, arrays {@link ArrayList}, integers {@link Long}
 * (or {@link Double} when they do not fit), other numbers {@link Double}.
 */
final class Json {

    private static final int MAX_DEPTH = 64;
    /**
     * Most values in one document. Real token, UserInfo, metadata and key-set documents hold a few
     * hundred; the limit keeps a padded answer ({@code [{},{},...]}) from becoming megabytes of objects.
     */
    static final int MAX_VALUES = 10000;

    private Json() {
    }

    static Object parse(String text) {
        Parser p = new Parser(text);
        p.skipWhitespace();
        Object value = p.readValue(0);
        p.skipWhitespace();
        if (p.pos != text.length()) {
            throw p.error("Unexpected trailing content");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("Expected a JSON object");
        }
        return (Map<String, Object>) value;
    }

    static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(value, sb);
        return sb.toString();
    }

    private static void write(Object value, StringBuilder sb) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            writeString((String) value, sb);
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(String.valueOf(e.getKey()), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
        } else if (value instanceof Collection) {
            sb.append('[');
            boolean first = true;
            for (Object o : (Collection<?>) value) {
                if (!first) sb.append(',');
                first = false;
                write(o, sb);
            }
            sb.append(']');
        } else {
            writeString(value.toString(), sb);
        }
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        private final String s;
        private int pos;
        private int values;

        Parser(String s) {
            if (s == null) {
                throw new IllegalArgumentException("JSON text is null");
            }
            this.s = s;
        }

        Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("Nesting too deep");
            }
            if (++values > MAX_VALUES) {
                throw error("More than " + MAX_VALUES + " values");
            }
            if (pos >= s.length()) {
                throw error("Unexpected end of input");
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{': return readObject(depth);
                case '[': return readArray(depth);
                case '"': return readString();
                case 't': expect("true"); return Boolean.TRUE;
                case 'f': expect("false"); return Boolean.FALSE;
                case 'n': expect("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return readNumber();
                    }
                    throw error("Unexpected character '" + c + "'");
            }
        }

        private Map<String, Object> readObject(int depth) {
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            pos++;
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw error("Expected string key");
                }
                String key = readString();
                skipWhitespace();
                if (peek() != ':') {
                    throw error("Expected ':'");
                }
                pos++;
                skipWhitespace();
                map.put(key, readValue(depth + 1));
                skipWhitespace();
                char c = peek();
                pos++;
                if (c == '}') return map;
                if (c != ',') throw error("Expected ',' or '}'");
            }
        }

        private List<Object> readArray(int depth) {
            List<Object> list = new ArrayList<Object>();
            pos++;
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWhitespace();
                list.add(readValue(depth + 1));
                skipWhitespace();
                char c = peek();
                pos++;
                if (c == ']') return list;
                if (c != ',') throw error("Expected ',' or ']'");
            }
        }

        private String readString() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw error("Unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= s.length()) throw error("Unterminated escape");
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            char u = readHex4();
                            if (Character.isHighSurrogate(u)) {
                                // a pair must follow as a second escape; lone surrogates are not text
                                if (!s.startsWith("\\u", pos)) throw error("Unpaired surrogate in unicode escape");
                                pos += 2;
                                char low = readHex4();
                                if (!Character.isLowSurrogate(low)) throw error("Unpaired surrogate in unicode escape");
                                sb.append(u).append(low);
                            } else if (Character.isLowSurrogate(u)) {
                                throw error("Unpaired surrogate in unicode escape");
                            } else {
                                sb.append(u);
                            }
                            break;
                        default:
                            throw error("Bad escape '\\" + e + "'");
                    }
                } else if (c < 0x20) {
                    throw error("Control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        /** Exactly four hex digits, no sign (Integer.parseInt would accept "+069"). */
        private char readHex4() {
            if (pos + 4 > s.length()) throw error("Bad unicode escape");
            int v = 0;
            for (int i = 0; i < 4; i++) {
                char h = s.charAt(pos + i);
                int d = h >= '0' && h <= '9' ? h - '0'
                        : h >= 'a' && h <= 'f' ? h - 'a' + 10
                        : h >= 'A' && h <= 'F' ? h - 'A' + 10 : -1; // ASCII only, unlike Character.digit
                if (d < 0) throw error("Bad unicode escape");
                v = v * 16 + d;
            }
            pos += 4;
            return (char) v;
        }

        /** RFC 8259: {@code -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?}, finite. */
        private Number readNumber() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') pos++;
            int intStart = pos;
            skipDigits();
            int intDigits = pos - intStart;
            if (intDigits == 0 || (intDigits > 1 && s.charAt(intStart) == '0')) {
                throw error("Bad number '" + s.substring(start, pos) + "'");
            }
            boolean integral = true;
            if (pos < s.length() && s.charAt(pos) == '.') {
                integral = false;
                pos++;
                if (skipDigits() == 0) throw error("Bad number '" + s.substring(start, pos) + "'");
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                integral = false;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
                if (skipDigits() == 0) throw error("Bad number '" + s.substring(start, pos) + "'");
            }
            String num = s.substring(start, pos);
            if (integral) {
                try {
                    return Long.parseLong(num);
                } catch (NumberFormatException overflow) {
                    // fall through: too large for a long
                }
            }
            double d = Double.parseDouble(num);
            if (Double.isInfinite(d) || Double.isNaN(d)) {
                throw error("Number out of range '" + num + "'");
            }
            return d;
        }

        private int skipDigits() {
            int from = pos;
            while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
            return pos - from;
        }

        private void expect(String word) {
            if (!s.startsWith(word, pos)) {
                throw error("Expected '" + word + "'");
            }
            pos += word.length();
        }

        private char peek() {
            if (pos >= s.length()) {
                throw error("Unexpected end of input");
            }
            return s.charAt(pos);
        }

        void skipWhitespace() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        IllegalArgumentException error(String msg) {
            return new IllegalArgumentException("Invalid JSON at position " + pos + ": " + msg);
        }
    }
}
