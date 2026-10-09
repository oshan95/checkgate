package com.oshan.checkgate.rag;

import com.oshan.checkgate.embedding.EmbeddingService;
import com.oshan.checkgate.model.ReferenceEntry;
import com.oshan.checkgate.model.RetrievedReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RagRetrievalService {

    public record RetrievalResult(String description, List<RetrievedReference> references,
                                  boolean lowConfidence) { }

    private final GeminiAnalysisService analysisService;
    private final EmbeddingService embeddingService;
    private final VectorSearchService vectorSearchService;

    @Value("${checkgate.rag.min-similarity:0.80}")
    private double minSimilarity;

    @Value("${checkgate.rag.top-n:5}")
    private int topN;

    public RagRetrievalService(GeminiAnalysisService analysisService, EmbeddingService embeddingService,
                               VectorSearchService vectorSearchService) {
        this.analysisService = analysisService;
        this.embeddingService = embeddingService;
        this.vectorSearchService = vectorSearchService;
    }

    // Describe the code in words, embed that, search, and flag weak or empty retrieval.
    public RetrievalResult retrieveForCode(String annotatedCode) {
        String description = analysisService.describeForRetrieval(annotatedCode);
        if ("NONE".equalsIgnoreCase(description)) {
            return new RetrievalResult(description, List.of(), true);
        }
        List<RetrievedReference> refs =
                vectorSearchService.findRelevant(embeddingService.embed(description), topN);
        boolean weak = refs.isEmpty() || refs.get(0).similarity() < minSimilarity;
        return new RetrievalResult(description, refs, weak);
    }
}
