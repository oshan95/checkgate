package com.oshan.checkgate.github;

import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.model.FileDiff;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ScanController {

    private final DiffExtractionService diffExtractionService;

    public ScanController(DiffExtractionService diffExtractionService) {
        this.diffExtractionService =  diffExtractionService;
    }

    //Receives the scan request triggered by the GitHub Actions workflow
    @PostMapping("/scan")
    public String triggerScan(@RequestBody String prPayload) {
        List<FileDiff> files = diffExtractionService.extractDiff(prPayload);
        return "Extracted " + files.size() + " file(s) from diff";
    }

}
