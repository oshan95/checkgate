package com.oshan.checkgate.ingestion;

import com.oshan.checkgate.embedding.EmbeddingService;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.util.List;

@Component
public class NvdIngestionJob {

    private final NvdApiClient nvdApiClient;
    private final EmbeddingService embeddingService;
    private final ReferenceEntryRepository referenceEntryRepository;

    public NvdIngestionJob(NvdApiClient nvdApiClient, EmbeddingService embeddingService
            , ReferenceEntryRepository referenceEntryRepository) {
        this.nvdApiClient = nvdApiClient;
        this.embeddingService = embeddingService;
        this.referenceEntryRepository = referenceEntryRepository;
    }

    // Scheduled job pulling new/updated CVE entries from the NVD
    @Scheduled(cron = "0 0 2 * * *")
    public void runIngestion() {
        OffsetDateTime since = OffsetDateTime.now().minusHours(48);
        List<NvdApiClient.NvdCveEntry> entries = nvdApiClient.fetchModifiedSince(since);

        int batchSize = 5; // conservative — verify actual limit against real API responses
        for (int i = 0; i < entries.size(); i += batchSize) {
            List<NvdApiClient.NvdCveEntry> chunk = entries.subList(i, Math.min(i + batchSize, entries.size()));
            List<String> descriptions = chunk.stream().map(NvdApiClient.NvdCveEntry::description).toList();

            List<float[]> embeddings = embeddingService.embedBatch(descriptions);

            for (int j = 0; j < chunk.size(); j++) {
                var entry = chunk.get(j);
                referenceEntryRepository.upsert(entry.id(), "CVE", entry.id(),
                        entry.description(), embeddings.get(j), entry.lastModified().toLocalDate());
            }
        }
    }

}
