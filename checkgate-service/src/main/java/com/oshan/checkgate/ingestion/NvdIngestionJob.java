package com.oshan.checkgate.ingestion;

import com.oshan.checkgate.embedding.EmbeddingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Profile;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

@Component
@Profile("!eval")
public class NvdIngestionJob {

    private static final Logger log = LoggerFactory.getLogger(NvdIngestionJob.class);
    private static final String SOURCE = "CVE";
    private static final int BATCH_SIZE = 5;
    private static final long BATCH_DELAY_MS = 3500; // 5 texts per batch, stays under 100 per minute

    private final NvdApiClient nvdApiClient;
    private final EmbeddingService embeddingService;
    private final ReferenceEntryRepository repository;

    public NvdIngestionJob(NvdApiClient nvdApiClient, EmbeddingService embeddingService,
                           ReferenceEntryRepository repository) {
        this.nvdApiClient = nvdApiClient;
        this.embeddingService = embeddingService;
        this.repository = repository;
    }

    @Scheduled(cron = "0 0 2 * * *", zone = "Pacific/Auckland")
    public void runIngestion() {
        // 48h lookback, wider than the daily schedule, so a missed run never skips a CVE
        OffsetDateTime since = OffsetDateTime.now().minusHours(48);
        List<NvdApiClient.NvdCveEntry> entries = nvdApiClient.fetchModifiedSince(since);

        // Skip entries already stored with the same description (saves quota)
        Map<String, String> existing = repository.findDescriptionsBySource(SOURCE);
        List<NvdApiClient.NvdCveEntry> changed = entries.stream()
                .filter(e -> !e.description().equals(existing.get(e.id())))
                .toList();
        log.info("NVD returned {} entries, {} new or changed", entries.size(), changed.size());

        for (int i = 0; i < changed.size(); i += BATCH_SIZE) {
            List<NvdApiClient.NvdCveEntry> chunk = changed.subList(i, Math.min(i + BATCH_SIZE, changed.size()));
            List<String> descriptions = chunk.stream().map(NvdApiClient.NvdCveEntry::description).toList();
            List<float[]> embeddings = embeddingService.embedBatchWithRetry(descriptions);

            for (int j = 0; j < chunk.size(); j++) {
                var entry = chunk.get(j);
                repository.upsert(entry.id(), SOURCE, entry.id(), entry.description(),
                        embeddings.get(j), entry.lastModified().toLocalDate());
            }
            log.info("Stored {}/{}", Math.min(i + BATCH_SIZE, changed.size()), changed.size());
            sleep(BATCH_DELAY_MS);
        }
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
