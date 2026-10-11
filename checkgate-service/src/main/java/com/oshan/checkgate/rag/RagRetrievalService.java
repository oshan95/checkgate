package com.oshan.checkgate.rag;

import com.oshan.checkgate.embedding.EmbeddingService;
import com.oshan.checkgate.model.ReferenceEntry;
import com.oshan.checkgate.model.RetrievedReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RagRetrievalService {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RagRetrievalService.class);

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
        long t0 = System.currentTimeMillis();
        String description = analysisService.describeForRetrieval(annotatedCode);
        long t1 = System.currentTimeMillis();
        if ("NONE".equalsIgnoreCase(description)) {
            log.info("RAG timing: describe={}ms (NONE)", t1 - t0);
            return new RetrievalResult(description, List.of(), true);
        }
        float[] vector = embeddingService.embed(description);
        long t2 = System.currentTimeMillis();
        List<RetrievedReference> refs = vectorSearchService.findRelevant(vector, topN);
        long t3 = System.currentTimeMillis();
        log.info("RAG timing: describe={}ms embed={}ms search={}ms", t1 - t0, t2 - t1, t3 - t2);

        boolean weak = refs.isEmpty() || refs.get(0).similarity() < minSimilarity;
        return new RetrievalResult(description, refs, weak);
    }
}
