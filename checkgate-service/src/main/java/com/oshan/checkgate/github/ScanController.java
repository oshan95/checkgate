package com.oshan.checkgate.github;

import com.oshan.checkgate.aggregation.ResultAggregationService;
import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.diff.GuardRailService;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.ScanFileResult;
import com.oshan.checkgate.scan.ScanPipelineService;
import com.oshan.checkgate.scan.ScanService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ScanService scanService;
    private final ThreadPoolTaskExecutor scanExecutor;

    public ScanController(ScanService scanService,
                          @Qualifier("scanExecutor") ThreadPoolTaskExecutor scanExecutor) {
        this.scanService = scanService;
        this.scanExecutor = scanExecutor;
    }

    // Accepts the scan request and returns immediately; the scan runs in the background
    @PostMapping("/scan")
    public ResponseEntity<String> triggerScan(@RequestBody ScanRequest request) {
        try {
            scanExecutor.execute(() -> runSafely(request));
        } catch (TaskRejectedException e) {
            log.warn("Scan queue full, rejecting request for PR #{}", request.prNumber());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("CheckGate is busy, try again shortly");
        }
        return ResponseEntity.accepted().body("Scan accepted");
    }

    private void runSafely(ScanRequest request) {
        try {
            scanService.process(request);
        } catch (Exception e) {
            log.error("Scan failed for {}/{} PR #{}",
                    request.repoOwner(), request.repoName(), request.prNumber(), e);
        }
    }

}
