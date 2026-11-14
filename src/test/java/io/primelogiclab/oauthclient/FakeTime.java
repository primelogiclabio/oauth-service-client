package io.primelogiclab.oauthclient;

import com.github.benmanes.caffeine.cache.Ticker;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

/** A clock and Caffeine ticker that move together, only when a test says so. */
final class FakeTime extends Clock implements Ticker {

    static final Instant START = Instant.parse("2026-11-14T10:00:00Z");

    private final AtomicLong nanos = new AtomicLong();

    void advance(Duration d) {
        nanos.addAndGet(d.toNanos());
    }

    @Override
    public long read() {
        return nanos.get();
    }

    @Override
    public Instant instant() {
        return START.plusNanos(nanos.get());
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException();
    }
}
