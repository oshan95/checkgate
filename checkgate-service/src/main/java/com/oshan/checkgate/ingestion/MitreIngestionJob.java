package com.oshan.checkgate.ingestion;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class MitreIngestionJob {

    // Scheduled job pulling new/updated CWE entries from MITRE.
    // TODO (#11): implement MITRE polling, embedding, and storage.
    @Scheduled(cron = "0 30 2 * * *")
    public void runIngestion() {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
