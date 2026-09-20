package com.oshan.checkgate.github;

import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.model.FileDiff;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ScanController {

    private final DiffExtractionService diffExtractionService;
    private final DiffFilterService diffFilterService;

    public ScanController(DiffExtractionService diffExtractionService, DiffFilterService diffFilterService) {
        this.diffExtractionService =  diffExtractionService;
        this.diffFilterService = diffFilterService;
    }

    //Receives the scan request triggered by the GitHub Actions workflow
    @PostMapping("/scan")
    public String triggerScan(@RequestBody String prPayload) {
        List<FileDiff> files = diffExtractionService.extractDiff(prPayload);

        List<FileDiff> filesToScan = files.stream()
                .filter(diffFilterService::shouldScan)
                .toList();

        return "Extracted " + files.size() + " file(s), " + filesToScan.size() + " after filtering";
    }

}
