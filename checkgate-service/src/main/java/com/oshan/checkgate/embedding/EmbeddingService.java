package com.oshan.checkgate.embedding;

import com.google.genai.Client;
import com.google.genai.types.ContentEmbedding;
import com.google.genai.types.EmbedContentResponse;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmbeddingService {

    private static final String EMBEDDING_MODEL = "gemini-embedding-001";

    private final Client geminiClient;

    public EmbeddingService(Client geminiClient) {
        this.geminiClient = geminiClient;
    }

    // Used both by the ingestion job (embedding reference entries) and at scan time for the code diff.
    // Must stay the same model for both sides, or similarity search wouldn't work.

    public float[] embed(String text) {
        EmbedContentResponse response = geminiClient.models.embedContent(EMBEDDING_MODEL, text, null);

        List<ContentEmbedding> embeddings = response.embeddings()
                .orElseThrow(() -> new IllegalStateException("No embedding returned from Gemini"));
        List<Float> values = embeddings.get(0).values()
                .orElseThrow(() -> new IllegalStateException("Embedding response had no values"));

        float[] result = new float[values.size()];
        for (int i = 0; i < values.size(); i++) {
            result[i] = values.get(i);
        }
        return result;
    }

    // Batch embed contents
    public List<float[]> embedBatch(List<String> texts) {
        EmbedContentResponse response = geminiClient.models.embedContent(EMBEDDING_MODEL, texts, null);

        List<ContentEmbedding> embeddings = response.embeddings()
                .orElseThrow(() -> new IllegalStateException("No embeddings returned from Gemini"));

        return embeddings.stream()
                .map(e -> {
                    List<Float> values = e.values().orElseThrow();
                    float[] result = new float[values.size()];
                    for (int i = 0; i < values.size(); i++) result[i] = values.get(i);
                    return result;
                })
                .toList();
    }

}
