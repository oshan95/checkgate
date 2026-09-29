package com.oshan.checkgate.github;

import com.oshan.checkgate.aggregation.ResultAggregationService;
import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.diff.GuardRailService;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Controller;
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

    public ScanController(DiffExtractionService diffExtractionService, DiffFilterService diffFilterService
            , GuardRailService guardRailService, ResultAggregationService resultAggregationService) {
        this.diffExtractionService =  diffExtractionService;
        this.diffFilterService = diffFilterService;
        this.guardRailService = guardRailService;
        this.resultAggregationService = resultAggregationService;
    }

    //Receives the scan request triggered by the GitHub Actions workflow
    @PostMapping("/scan")
    public String triggerScan(@RequestBody String prPayload) {
        List<FileDiff> files = diffExtractionService.extractDiff(prPayload);

        if (guardRailService.exceedsSizeLimit(files)) {
            return "Change too large for automated scan — manual review recommended.";
        }

        List<FileDiff> filesToScan = files.stream()
                .filter(diffFilterService::shouldScan)
                .toList();

        // TODO: replace the empty list with real Gemini calls
        List<VulnerabilityFinding> findings = List.of(); // placeholder until wired to Gemini

        return resultAggregationService.buildPrComment(findings);
    }

}
