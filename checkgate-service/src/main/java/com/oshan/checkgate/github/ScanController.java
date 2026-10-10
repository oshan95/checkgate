package com.oshan.checkgate.github;

import com.oshan.checkgate.aggregation.ResultAggregationService;
import com.oshan.checkgate.diff.DiffExtractionService;
import com.oshan.checkgate.diff.DiffFilterService;
import com.oshan.checkgate.diff.GuardRailService;
import com.oshan.checkgate.embedding.EmbeddingService;
import com.oshan.checkgate.embedding.LineAnnotationService;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.VulnerabilityFinding;
import com.oshan.checkgate.rag.GeminiAnalysisService;
import com.oshan.checkgate.rag.GeminiResponseParser;
import com.oshan.checkgate.rag.RagRetrievalService;
import com.oshan.checkgate.rag.VectorSearchService;
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

    private final GeminiAnalysisService geminiAnalysisService;
    private final GeminiResponseParser geminiResponseParser;

    private final VectorSearchService vectorSearchService;
    private final EmbeddingService embeddingService;
    private final RagRetrievalService ragRetrievalService;
    private final LineAnnotationService lineAnnotationService;

    public ScanController(DiffExtractionService diffExtractionService, DiffFilterService diffFilterService
            , GuardRailService guardRailService, ResultAggregationService resultAggregationService
            , GitHubCommentService gitHubCommentService, GeminiAnalysisService geminiAnalysisService
            , GeminiResponseParser geminiResponseParser, VectorSearchService vectorSearchService
            , EmbeddingService embeddingService, RagRetrievalService ragRetrievalService
            , LineAnnotationService lineAnnotationService) {
        this.diffExtractionService =  diffExtractionService;
        this.diffFilterService = diffFilterService;
        this.guardRailService = guardRailService;
        this.resultAggregationService = resultAggregationService;
        this.gitHubCommentService = gitHubCommentService;
        this.geminiAnalysisService = geminiAnalysisService;
        this.geminiResponseParser = geminiResponseParser;
        this.vectorSearchService = vectorSearchService;
        this.embeddingService = embeddingService;
        this.ragRetrievalService =  ragRetrievalService;
        this.lineAnnotationService = lineAnnotationService;
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

    @GetMapping("/test-analysis")
    public String testAnalysis() throws Exception {
        String diff = """
            1: String q = "SELECT * FROM users WHERE id = '" + request.getParameter("id") + "'";
            2: Statement st = connection.createStatement();
            3: ResultSet rs = st.executeQuery(q);
            """;
        String context = "CWE-89: SQL Injection. The product constructs all or part of an SQL "
                + "command using externally-influenced input.";

        var response = geminiAnalysisService.analyze(diff, context);
        return response.text() + "\n---\n" + geminiResponseParser.parse(response);
    }

    @PostMapping("/test-search")
    public String testSearch(@RequestBody String code) {
        var r = ragRetrievalService.retrieveForCode(code);
        return "lowConfidence=" + r.lowConfidence() + "\n" + r.description() + "\n---\n"
                + r.references().stream()
                .map(x -> "%.3f  %s  %s".formatted(x.similarity(), x.id(), x.title()))
                .collect(java.util.stream.Collectors.joining("\n"));
    }

    @PostMapping("/test-annotate")
    public String testAnnotate(@RequestBody String rawDiff) {
        return diffExtractionService.extractDiff(rawDiff).stream()
                .map(lineAnnotationService::annotate)
                .map(a -> a.filePath() + "\nadded=" + a.addedLines() + "\nvisible=" + a.visibleLines()
                        + "\n" + a.annotatedText())
                .collect(java.util.stream.Collectors.joining("\n=====\n"));
    }

}
