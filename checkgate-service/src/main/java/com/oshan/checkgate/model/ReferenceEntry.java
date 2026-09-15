package com.oshan.checkgate.model;

import java.time.LocalDate;

public record ReferenceEntry(
        String id,            // e.g. "CWE-89"
        String sourceType,    // "CWE" or "CVE"
        String title,
        String description,
        float[] embedding,
        LocalDate lastUpdated
) { }
