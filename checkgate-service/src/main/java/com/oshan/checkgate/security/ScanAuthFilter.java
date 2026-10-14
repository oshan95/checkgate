package com.oshan.checkgate.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// Rejects any /scan request that does not carry the shared secret. Fails closed:
// with no token configured, every /scan request is rejected
@Component
public class ScanAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ScanAuthFilter.class);
    private static final String HEADER = "X-CheckGate-Token";

    private final byte[] expected;

    public ScanAuthFilter(@Value("${checkgate.scan.api-token:}") String token) {
        this.expected = token.getBytes(StandardCharsets.UTF_8);
        if (token.isBlank()) {
            log.warn("checkgate.scan.api-token is not set: every /scan request will be rejected");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/scan".equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String supplied = request.getHeader(HEADER);
        boolean ok = expected.length > 0 && supplied != null
                && MessageDigest.isEqual(expected, supplied.getBytes(StandardCharsets.UTF_8));
        if (!ok) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }

}
