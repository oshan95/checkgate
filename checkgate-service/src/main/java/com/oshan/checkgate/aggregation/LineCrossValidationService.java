package com.oshan.checkgate.aggregation;

import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

@Service
public class LineCrossValidationService {

    // A reported line that is not a numbered line of the diff cannot be right: flag it.
    public boolean isLineWithinDiff(int reportedLine, Set<Integer> visibleLines) {
        return visibleLines.contains(reportedLine);
    }

    public List<VulnerabilityFinding> validate(List<VulnerabilityFinding> findings, Set<Integer> visibleLines) {
        return findings.stream()
                .map(f -> new VulnerabilityFinding(f.vulnerabilityType(), f.severity(), f.reasoning(),
                        f.reportedLine(), f.lowConfidence() || !isLineWithinDiff(f.reportedLine(), visibleLines)))
                .toList();
    }

}
