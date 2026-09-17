package com.oshan.checkgate.rag;

import com.oshan.checkgate.model.ReferenceEntry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VectorSearchService {

    // Cosine-similarity query against the vector store (pgvector <=> operator).
    // TODO: implement similarity search, returning the top matches.
    public List<ReferenceEntry> findRelevant(float[] queryEmbedding, int topN) {
        throw new UnsupportedOperationException("Not yet implemente.");
    }
}
