package com.oshan.checkgate.embedding;

import com.google.genai.Client;
import com.google.genai.types.ContentEmbedding;
import com.google.genai.types.EmbedContentResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmbeddingService {

    private static final Logger log = LoggerFactory.getLogger(EmbeddingService.class);

    private static final int MAX_RETRIES = 3;

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

    public List<float[]> embedBatchWithRetry(List<String> texts) {
        int attempt = 0;
        while (true) {
            try {
                return embedBatch(texts);
            } catch (com.google.genai.errors.ClientException e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if (!msg.startsWith("429")) throw e;
                if (msg.contains("PerDay")) {
                    // Waiting 30s can't fix a daily cap, so stop and let the next run resume
                    throw new IllegalStateException(
                            "Gemini daily embedding quota exhausted; ingestion resumes on the next run", e);
                }
                if (++attempt > MAX_RETRIES) throw e;
                log.warn("Gemini per-minute rate limit (429), waiting 30s, attempt {}", attempt);
                pause(30_000);
            } catch (com.google.genai.errors.GenAiIOException e) {
                if (++attempt > MAX_RETRIES) throw e;
                log.warn("Gemini network error, retrying in {}s, attempt {}: {}", 5 * attempt, attempt, e.getMessage());
                pause(5_000L * attempt);
            }
        }
    }

    private void pause(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

}
