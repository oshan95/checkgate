package com.oshan.checkgate.scan;

import com.google.genai.types.GenerateContentResponse;
import com.oshan.checkgate.aggregation.LineCrossValidationService;
import com.oshan.checkgate.embedding.LineAnnotationService;
import com.oshan.checkgate.model.FileDiff;
import com.oshan.checkgate.model.RetrievedReference;
import com.oshan.checkgate.model.ScanFileResult;
import com.oshan.checkgate.model.VulnerabilityFinding;
import com.oshan.checkgate.rag.GeminiAnalysisService;
import com.oshan.checkgate.rag.GeminiResponseParser;
import com.oshan.checkgate.rag.RagRetrievalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// The Gemini and database services are replaced by mocks, so these tests need no network, no key and no database.
class ScanPipelineServiceTest {

    private static final FileDiff ADDED = new FileDiff("A.java", "@@ -0,0 +1,2 @@\n+int a = 1;\n+int b = 2;\n");
    private static final FileDiff ONLY_REMOVED = new FileDiff("B.java", "@@ -1,2 +0,0 @@\n-int a = 1;\n-int b = 2;\n");
    private static final VulnerabilityFinding FINDING = new VulnerabilityFinding("CWE-20", "LOW", "reason", 1, false);

    private RagRetrievalService rag;
    private GeminiAnalysisService analysis;
    private GeminiResponseParser parser;
    private ScanPipelineService pipeline;

    @BeforeEach
    void setUp() throws Exception {
        rag = mock(RagRetrievalService.class);
        analysis = mock(GeminiAnalysisService.class);
        parser = mock(GeminiResponseParser.class);
        when(parser.parse(any())).thenReturn(List.of(FINDING));
        pipeline = new ScanPipelineService(new LineAnnotationService(), rag, analysis, parser, new LineCrossValidationService());
    }

    private void retrievalReturns(boolean lowConfidence) {
        RetrievedReference ref = new RetrievedReference("CWE-798", "CWE", "Use of Hard-coded Credentials", "A description", 0.86);
        when(rag.retrieveForCode(anyString())).thenReturn(
                new RagRetrievalService.RetrievalResult("Hard-coded credentials", List.of(ref), lowConfidence));
    }

    private String contextSentToTheModel() {
        ArgumentCaptor<String> context = ArgumentCaptor.forClass(String.class);
        verify(analysis).analyze(anyString(), context.capture());
        return context.getValue();
    }

    @Test
    void aConfidentMatchPutsTheReferencesInThePrompt() throws Exception {
        retrievalReturns(false);
        ScanPipelineService.FileAnalysis result = pipeline.analyzeFile(ADDED, ScanPipelineService.ReferenceMode.WITH_REFERENCES);
        assertTrue(result.grounded());
        assertEquals("Hard-coded credentials", result.description());
        assertEquals(1, result.references().size());
        String context = contextSentToTheModel();
        assertTrue(context.contains("CWE-798"));
        assertTrue(context.contains("Use of Hard-coded Credentials"));
        assertFalse(context.contains("do not guess"));
    }

    @Test
    void aWeakMatchFallsBackToTheStandardWording() throws Exception {
        retrievalReturns(true);
        ScanPipelineService.FileAnalysis result = pipeline.analyzeFile(ADDED, ScanPipelineService.ReferenceMode.WITH_REFERENCES);
        assertFalse(result.grounded());
        assertTrue(contextSentToTheModel().contains("No reliable reference entries"));
    }

    @Test
    void theStandardModeNeverRetrievesAndKeepsTheCautionWording() throws Exception {
        ScanPipelineService.FileAnalysis result = pipeline.analyzeFile(ADDED, ScanPipelineService.ReferenceMode.STANDARD_NO_REFERENCES);
        assertFalse(result.grounded());
        verify(rag, never()).retrieveForCode(any());
        assertTrue(contextSentToTheModel().contains("do not guess a specific CWE"));
    }

    @Test
    void theNeutralModeNeverRetrievesAndGivesOnlyAPlainLine() throws Exception {
        ScanPipelineService.FileAnalysis result = pipeline.analyzeFile(ADDED, ScanPipelineService.ReferenceMode.NEUTRAL_NO_REFERENCES);
        assertFalse(result.grounded());
        verify(rag, never()).retrieveForCode(any());
        assertEquals("No reference entries are provided for this code.", contextSentToTheModel());
    }

    @Test
    void aDiffThatOnlyRemovesLinesIsNeverSentToTheModel() throws Exception {
        ScanPipelineService.FileAnalysis result = pipeline.analyzeFile(ONLY_REMOVED, ScanPipelineService.ReferenceMode.WITH_REFERENCES);
        assertTrue(result.findings().isEmpty());
        verify(rag, never()).retrieveForCode(any());
        verify(analysis, never()).analyze(any(), any());
    }

    @Test
    void oneFailingFileDoesNotFailTheWholeScan() throws Exception {
        retrievalReturns(false);
        org.mockito.Mockito.doThrow(new RuntimeException("boom")).doReturn((GenerateContentResponse) null)
                .when(analysis).analyze(anyString(), anyString());
        List<ScanFileResult> results = pipeline.scanFiles(List.of(ADDED, ADDED));
        assertEquals(2, results.size());
        assertTrue(results.get(0).failed());
        assertFalse(results.get(1).failed());
        assertEquals(1, results.get(1).findings().size());
    }
}
