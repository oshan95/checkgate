package com.oshan.checkgate.scan;

import com.oshan.checkgate.aggregation.ResultAggregationService;
import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.diff.GuardRailService;
import com.oshan.checkgate.github.GitHubCommentService;
import com.oshan.checkgate.github.ScanRequest;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.ScanFileResult;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ScanService {

    private final DiffExtractionService diffExtractionService;
    private final DiffFilterService diffFilterService;
    private final GuardRailService guardRailService;
    private final ScanPipelineService scanPipelineService;
    private final ResultAggregationService resultAggregationService;
    private final GitHubCommentService gitHubCommentService;

    public ScanService(DiffExtractionService diffExtractionService, DiffFilterService diffFilterService,
                       GuardRailService guardRailService, ScanPipelineService scanPipelineService,
                       ResultAggregationService resultAggregationService,
                       GitHubCommentService gitHubCommentService) {
        this.diffExtractionService = diffExtractionService;
        this.diffFilterService = diffFilterService;
        this.guardRailService = guardRailService;
        this.scanPipelineService = scanPipelineService;
        this.resultAggregationService = resultAggregationService;
        this.gitHubCommentService = gitHubCommentService;
    }

    public void process(ScanRequest request) {
        List<FileDiff> files = diffExtractionService.extractDiff(request.diff());

        String comment;
        if (guardRailService.exceedsSizeLimit(files)) {
            comment = "**CheckGate**: Change too large for automated scan. Manual review recommended.";
        } else {
            List<FileDiff> filesToScan = files.stream().filter(diffFilterService::shouldScan).toList();
            List<ScanFileResult> results = scanPipelineService.scanFiles(filesToScan);
            comment = resultAggregationService.buildPrComment(results);
        }

        gitHubCommentService.postComment(request.repoOwner(), request.repoName(), request.prNumber(), comment);
    }

}
