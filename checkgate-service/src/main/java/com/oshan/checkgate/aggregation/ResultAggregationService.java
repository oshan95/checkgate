package com.oshan.checkgate.aggregation;

import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ResultAggregationService {

    // Aggregates findings across all scanned files into one PR comment.
    public String buildPrComment(List<VulnerabilityFinding> findings) {
        if (findings.isEmpty()) {
            return "**CheckGate**: No vulnerabilities detected in this pull request. ✅";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("**CheckGate found ").append(findings.size())
                .append(" potential issue(s):**\n\n");

        for (VulnerabilityFinding finding : findings) {
            sb.append("---\n");
            sb.append("**Type:** ").append(finding.vulnerabilityType()).append("\n");
            sb.append("**Severity:** ").append(finding.severity()).append("\n");
            sb.append("**Line:** ").append(finding.reportedLine());
            if (finding.lowConfidence()) {
                sb.append(" _(low confidence - pinpointed line may be incorrect)_");
            }
            sb.append("\n");
            sb.append("**Reasoning:** ").append(finding.reasoning()).append("\n");
        }

        return sb.toString();
    }

}
