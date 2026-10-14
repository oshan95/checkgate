package com.oshan.checkgate.config;

import com.google.genai.errors.ApiException;
import com.google.genai.errors.GenAiIOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

// Retries temporary Gemini failures (503, per-minute 429, network errors) with exponential backoff.
// A daily quota 429 is never retried: waiting a few seconds cannot fix it.
@Component
public class GeminiRetry {

    private static final Logger log = LoggerFactory.getLogger(GeminiRetry.class);
    private static final int MAX_RETRIES = 3;

    private final long baseDelayMs;

    public GeminiRetry(@Value("${checkgate.gemini.retry-base-delay-ms:2000}") long baseDelayMs) {
        this.baseDelayMs = baseDelayMs;
    }

    public <T> T call(String what, Supplier<T> action) {
        int attempt = 0;
        while (true) {
            try {
                return action.get();
            } catch (GenAiIOException e) {
                if (++attempt > MAX_RETRIES) throw e;
                backoff(what, attempt, "network error");
            } catch (ApiException e) {
                if (!isRetryable(e) || ++attempt > MAX_RETRIES) throw e;
                backoff(what, attempt, "HTTP " + e.code());
            }
        }
    }

    private boolean isRetryable(ApiException e) {
        if (e.code() == 503) return true;
        if (e.code() == 429) {
            String msg = e.getMessage() == null ? "" : e.getMessage();
            return !msg.contains("PerDay");
        }
        return false;
    }

    private void backoff(String what, int attempt, String reason) {
        long delay = baseDelayMs * (1L << (attempt - 1))
                + ThreadLocalRandom.current().nextLong(baseDelayMs / 2 + 1);
        log.warn("Gemini {} failed ({}), retrying in {}ms, attempt {}", what, reason, delay, attempt);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ie);
        }
    }
}