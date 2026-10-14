package com.oshan.checkgate.config;

import com.google.genai.errors.ApiException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GeminiRetryTest {

    private final GeminiRetry retry = new GeminiRetry(1);

    @Test
    void succeedsAfterTemporaryFailures() {
        AtomicInteger calls = new AtomicInteger();
        String result = retry.call("test", () -> {
            if (calls.incrementAndGet() < 3) throw new ApiException(503, "UNAVAILABLE", "busy");
            return "ok";
        });
        assertEquals("ok", result);
        assertEquals(3, calls.get());
    }

    @Test
    void givesUpAfterRetriesAreExhausted() {
        AtomicInteger calls = new AtomicInteger();
        assertThrows(ApiException.class, () -> retry.call("test", () -> {
            calls.incrementAndGet();
            throw new ApiException(503, "UNAVAILABLE", "busy");
        }));
        assertEquals(4, calls.get()); // first attempt plus three retries
    }

    @Test
    void doesNotRetryDailyQuota() {
        AtomicInteger calls = new AtomicInteger();
        assertThrows(ApiException.class, () -> retry.call("test", () -> {
            calls.incrementAndGet();
            throw new ApiException(429, "RESOURCE_EXHAUSTED", "GenerateRequestsPerDayPerProjectPerModel-FreeTier");
        }));
        assertEquals(1, calls.get());
    }

    @Test
    void doesNotRetryOtherClientErrors() {
        AtomicInteger calls = new AtomicInteger();
        assertThrows(ApiException.class, () -> retry.call("test", () -> {
            calls.incrementAndGet();
            throw new ApiException(400, "INVALID_ARGUMENT", "bad request");
        }));
        assertEquals(1, calls.get());
    }
}