package com.oshan.checkgate.model;

import java.util.List;

public record ScanFileResult(String filePath, List<VulnerabilityFinding> findings, boolean groundedByReferences,
                             boolean failed) {

    public static ScanFileResult failed(String filePath) {
        return new ScanFileResult(filePath, List.of(), false, true);
    }

}
