package com.oshan.checkgate.scan;

import com.oshan.checkgate.aggregation.LineCrossValidationService;
import com.oshan.checkgate.embedding.LineAnnotationService;
import com.oshan.checkgate.model.*;
import com.oshan.checkgate.rag.GeminiAnalysisService;
import com.oshan.checkgate.rag.GeminiResponseParser;
import com.oshan.checkgate.rag.RagRetrievalService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ScanPipelineService {

    private static final Logger log = LoggerFactory.getLogger(ScanPipelineService.class);
    private static final int MAX_REFERENCE_CHARS = 500;
    private static final String NO_CONTEXT = "No reliable reference entries were retrieved for this code. " +
            "Rely on general security knowledge and do not guess a specific CWE.";

    private final LineAnnotationService lineAnnotationService;
    private final RagRetrievalService ragRetrievalService;
    private final GeminiAnalysisService geminiAnalysisService;
    private final GeminiResponseParser geminiResponseParser;
    private final LineCrossValidationService lineCrossValidationService;

    public ScanPipelineService(LineAnnotationService lineAnnotationService, RagRetrievalService ragRetrievalService,
                               GeminiAnalysisService geminiAnalysisService, GeminiResponseParser geminiResponseParser,
                               LineCrossValidationService lineCrossValidationService) {
        this.lineAnnotationService = lineAnnotationService;
        this.ragRetrievalService = ragRetrievalService;
        this.geminiAnalysisService = geminiAnalysisService;
        this.geminiResponseParser = geminiResponseParser;
        this.lineCrossValidationService = lineCrossValidationService;
    }

    // One failing file never fails the whole scan.
    public List<ScanFileResult> scanFiles(List<FileDiff> files) {
        List<ScanFileResult> results = new ArrayList<>();
        for (FileDiff file : files) {
            long start = System.currentTimeMillis();
            try {
                results.add(scanFile(file));
                log.info("Scanned {} in {}ms", file.filePath(), System.currentTimeMillis() - start);
            } catch (Exception e) {
                log.error("Scan failed for {}", file.filePath(), e);
                results.add(ScanFileResult.failed(file.filePath()));
            }
        }
        return results;
    }

    private ScanFileResult scanFile(FileDiff file) throws Exception {

        AnnotatedDiff annotated = lineAnnotationService.annotate(file);

        // A diff that only removes lines cannot introduce a vulnerability
        if (annotated.addedLines().isEmpty()) {
            return new ScanFileResult(file.filePath(), List.of(), true, false);
        }

        var retrieval = ragRetrievalService.retrieveForCode(annotated.annotatedText());
        boolean grounded = !retrieval.lowConfidence();
        log.info("Retrieval for {}: description='{}' topSimilarity={} grounded={} refs={}",
                file.filePath(),
                retrieval.description(),
                retrieval.references().isEmpty() ? "n/a" : "%.3f".formatted(retrieval.references().get(0).similarity()),
                grounded,
                retrieval.references().stream().map(RetrievedReference::id).toList());
        String context = grounded ? formatReferences(retrieval.references()) : NO_CONTEXT;

        var response = geminiAnalysisService.analyze(annotated.annotatedText(), context);
        List<VulnerabilityFinding> findings = geminiResponseParser.parse(response);
        findings = lineCrossValidationService.validate(findings, annotated.visibleLines());

        return new ScanFileResult(file.filePath(), findings, grounded, false);
    }

    private String formatReferences(List<RetrievedReference> refs) {
        return refs.stream()
                .map(r -> "- " + r.id() + " (" + r.title() + "): " + truncate(r.description()))
                .collect(Collectors.joining("\n"));
    }

    private String truncate(String text) {
        return text.length() <= MAX_REFERENCE_CHARS ? text : text.substring(0, MAX_REFERENCE_CHARS) + "...";
    }

}
