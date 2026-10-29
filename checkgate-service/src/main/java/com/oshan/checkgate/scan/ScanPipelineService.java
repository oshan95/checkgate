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

    // Used only by the evaluation's neutral control: no reference text and no instruction either
    private static final String NEUTRAL_CONTEXT = "No reference entries are provided for this code.";

    // Everything one file analysis produced, kept so an evaluation can record the evidence as well as the findings
    public record FileAnalysis(List<VulnerabilityFinding> findings, boolean grounded, String description,
                               List<RetrievedReference> references, long retrievalMs, long analysisMs) { }

    // WITH_REFERENCES is a normal scan. The two others never retrieve anything: STANDARD uses the usual
    // "no reliable reference entries" wording, NEUTRAL uses a plain line with no instruction.
    public enum ReferenceMode { WITH_REFERENCES, STANDARD_NO_REFERENCES, NEUTRAL_NO_REFERENCES }

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
        FileAnalysis analysis = analyzeFile(file, ReferenceMode.WITH_REFERENCES);
        return new ScanFileResult(file.filePath(), analysis.findings(), analysis.grounded(), false);
    }

    // The steps of one file scan. A normal scan always uses WITH_REFERENCES. An evaluation can use the other two
    // modes to run the same prompt without any retrieval.
    public FileAnalysis analyzeFile(FileDiff file, ReferenceMode mode) throws Exception {

        AnnotatedDiff annotated = lineAnnotationService.annotate(file);

        // A diff that only removes lines cannot introduce a vulnerability
        if (annotated.addedLines().isEmpty()) {
            return new FileAnalysis(List.of(), true, null, List.of(), 0, 0);
        }

        long start = System.currentTimeMillis();
        boolean grounded = false;
        String description = null;
        List<RetrievedReference> references = List.of();

        if (mode == ReferenceMode.WITH_REFERENCES) {
            var retrieval = ragRetrievalService.retrieveForCode(annotated.annotatedText());
            grounded = !retrieval.lowConfidence();
            description = retrieval.description();
            references = retrieval.references();
            log.info("Retrieval for {}: description='{}' topSimilarity={} grounded={} refs={}",
                    file.filePath(),
                    retrieval.description(),
                    retrieval.references().isEmpty() ? "n/a" : "%.3f".formatted(retrieval.references().get(0).similarity()),
                    grounded,
                    retrieval.references().stream().map(RetrievedReference::id).toList());
        }
        String context = grounded ? formatReferences(references)
                : (mode == ReferenceMode.NEUTRAL_NO_REFERENCES ? NEUTRAL_CONTEXT : NO_CONTEXT);
        long afterRetrieval = System.currentTimeMillis();

        var response = geminiAnalysisService.analyze(annotated.annotatedText(), context);
        List<VulnerabilityFinding> findings = geminiResponseParser.parse(response);
        findings = lineCrossValidationService.validate(findings, annotated.visibleLines());

        return new FileAnalysis(findings, grounded, description, references,
                afterRetrieval - start, System.currentTimeMillis() - afterRetrieval);
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
