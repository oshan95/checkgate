package com.oshan.checkgate.rag;

import com.oshan.checkgate.model.ReferenceEntry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RagRetrievalService {

    private final VectorSearchService vectorSearchService;

    public RagRetrievalService(VectorSearchService vectorSearchService) {
        this.vectorSearchService = vectorSearchService;
    }

    // Wraps VectorSearchService; flags low-confidence when no sufficiently
    // relevant match is retrieved, rather than presenting an unsupported finding.
    // TODO: implement the confidence threshold and flagging logic.
    public List<ReferenceEntry> retrieveWithConfidenceCheck(float[] queryEmbedding) {
        throw new UnsupportedOperationException("Not yet implemented — see Issue #15");
    }
}
