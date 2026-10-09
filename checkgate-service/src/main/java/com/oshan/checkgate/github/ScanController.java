package com.oshan.checkgate.github;

import com.oshan.checkgate.aggregation.ResultAggregationService;
import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.diff.GuardRailService;
import com.oshan.checkgate.ingestion.MitreIngestionJob;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ScanController {

    private final DiffExtractionService diffExtractionService;
    private final DiffFilterService diffFilterService;
    private final GuardRailService guardRailService;
    private final ResultAggregationService resultAggregationService;
    private final GitHubCommentService gitHubCommentService;
    private final MitreIngestionJob mitreIngestionJob;

    public ScanController(DiffExtractionService diffExtractionService, DiffFilterService diffFilterService
            , GuardRailService guardRailService, ResultAggregationService resultAggregationService
            , GitHubCommentService gitHubCommentService, MitreIngestionJob mitreIngestionJob) {
        this.diffExtractionService =  diffExtractionService;
        this.diffFilterService = diffFilterService;
        this.guardRailService = guardRailService;
        this.resultAggregationService = resultAggregationService;
        this.gitHubCommentService = gitHubCommentService;
        this.mitreIngestionJob = mitreIngestionJob;
    }

    //Receives the scan request triggered by the GitHub Actions workflow
    @PostMapping("/scan")
    public String triggerScan(@RequestBody ScanRequest request) {
        List<FileDiff> files = diffExtractionService.extractDiff(request.diff());

        String comment;
        if (guardRailService.exceedsSizeLimit(files)) {
            comment = "Change too large for automated scan — manual review recommended.";
        } else {
            List<FileDiff> filesToScan = files.stream()
                    .filter(diffFilterService::shouldScan)
                    .toList();

            // TODO: replace the empty list with real Gemini calls
            List<VulnerabilityFinding> findings = List.of(); // placeholder until wired to Gemini

            comment = resultAggregationService.buildPrComment(findings);
        }

        gitHubCommentService.postComment(request.repoOwner(), request.repoName(), request.prNumber(), comment);
        return comment;
    }

}
