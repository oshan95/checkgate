package com.oshan.checkgate.aggregation;

import com.oshan.checkgate.model.ScanFileResult;
import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ResultAggregationService {

    // Aggregates findings across all scanned files into one PR comment.
    public String buildPrComment(List<ScanFileResult> results) {
        int total = results.stream().mapToInt(r -> r.findings().size()).sum();
        List<String> failed = results.stream()
                .filter(ScanFileResult::failed)
                .map(ScanFileResult::filePath)
                .toList();

        if (total == 0 && failed.isEmpty()) {
            return "**CheckGate**: No vulnerabilities detected in this pull request. ✅";
        }

        StringBuilder sb = new StringBuilder();
        if (total == 0) {
            sb.append("**CheckGate**: No vulnerabilities detected in the files that could be scanned.\n\n");
        } else {
            sb.append("**CheckGate found ").append(total).append(" potential issue(s):**\n\n");
        }

        for (ScanFileResult result : results) {
            if (result.findings().isEmpty()) continue;

            // Divider goes ABOVE the file heading so each file reads as its own section
            sb.append("---\n\n");
            sb.append("### `").append(result.filePath()).append("`\n\n");
            if (!result.groundedByReferences()) {
                sb.append("_No CWE/CVE reference met the similarity threshold for this file, "
                        + "so these findings rely on the model's general knowledge._\n\n");
            }

            List<VulnerabilityFinding> findings = result.findings();
            for (int i = 0; i < findings.size(); i++) {
                VulnerabilityFinding finding = findings.get(i);
                if (i > 0) {
                    sb.append("---\n\n"); // blank line before it, so it is never read as a heading underline
                }
                sb.append("**Type:** ").append(finding.vulnerabilityType()).append("  \n");
                sb.append("**Severity:** ").append(finding.severity()).append("  \n");
                sb.append("**Line:** ").append(finding.reportedLine());
                if (finding.lowConfidence()) {
                    sb.append(" _(low confidence - pinpointed line may be incorrect)_");
                }
                sb.append("  \n");
                sb.append("**Reasoning:** ").append(finding.reasoning()).append("\n\n");
            }
        }

        if (!failed.isEmpty()) {
            sb.append("---\n\n**Could not scan:** ").append(String.join(", ", failed)).append("\n");
        }
        return sb.toString();
    }

}
