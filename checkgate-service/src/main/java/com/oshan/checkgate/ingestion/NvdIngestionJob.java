package com.oshan.checkgate.ingestion;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class NvdIngestionJob {

    // Scheduled job pulling new/updated CVE entries from the NVD
    // TODO: implement NVD polling, embedding, and storage.
    @Scheduled(cron = "0 0 2 * * *") // every night at 2 am
    public void runIngestion() {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

}
