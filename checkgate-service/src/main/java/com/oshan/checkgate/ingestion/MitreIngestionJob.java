package com.oshan.checkgate.ingestion;

import com.oshan.checkgate.embedding.EmbeddingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class MitreIngestionJob {

    private static final Logger log = LoggerFactory.getLogger(MitreIngestionJob.class);
    private static final String SOURCE = "CWE";
    private static final int BATCH_SIZE = 5;
    private static final long BATCH_DELAY_MS = 3500; // same pacing as the NVD job

    private final CweApiClient cweApiClient;
    private final EmbeddingService embeddingService;
    private final ReferenceEntryRepository repository;

    public MitreIngestionJob(CweApiClient cweApiClient, EmbeddingService embeddingService,
                             ReferenceEntryRepository repository) {
        this.cweApiClient = cweApiClient;
        this.embeddingService = embeddingService;
        this.repository = repository;
    }

    // Scheduled job pulling new/updated CWE entries from MITRE.
    @Scheduled(cron = "0 30 2 * * *")
    public void runIngestion() {

        CweApiClient.CweVersion version = cweApiClient.fetchVersion();
        if (version.version().equals(repository.getIngestedVersion(SOURCE))) {
            log.info("CWE content {} already ingested, nothing to do", version.version());
            return;
        }

        List<CweApiClient.CweEntry> entries =
                cweApiClient.fetchJavaRelevant(cweApiClient.fetchWeaknessIds());

        // Skip entries already stored with the same description, so a new release
        // only re-embeds what actually changed.
        Map<String, String> existing = repository.findDescriptionsBySource(SOURCE);
        List<CweApiClient.CweEntry> changed = entries.stream()
                .filter(e -> !e.description().equals(existing.get(e.id())))
                .toList();
        log.info("CWE {}: {} relevant entries, {} new or changed",
                version.version(), entries.size(), changed.size());

        for (int i = 0; i < changed.size(); i += BATCH_SIZE) {
            List<CweApiClient.CweEntry> chunk = changed.subList(i, Math.min(i + BATCH_SIZE, changed.size()));
            List<float[]> embeddings = embeddingService.embedBatchWithRetry(
                    chunk.stream().map(CweApiClient.CweEntry::embeddingText).toList());

            for (int j = 0; j < chunk.size(); j++) {
                var e = chunk.get(j);
                repository.upsert(e.id(), SOURCE, e.name(), e.description(),
                        embeddings.get(j), version.date());
            }
            log.info("Stored {}/{}", Math.min(i + BATCH_SIZE, changed.size()), changed.size());
            sleep(BATCH_DELAY_MS);
        }

        // Saved last, so a failed run is retried tomorrow
        repository.saveIngestedVersion(SOURCE, version.version());
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
