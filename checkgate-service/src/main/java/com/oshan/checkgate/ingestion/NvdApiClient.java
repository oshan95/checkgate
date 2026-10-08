package com.oshan.checkgate.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Service
public class NvdApiClient {
    private static final Logger log = LoggerFactory.getLogger(NvdApiClient.class);

    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final DateTimeFormatter NVD_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${checkgate.ingestion.nvd-page-size:200}")
    private int pageSize;

    @Value("${checkgate.ingestion.nvd-max-pages:0}") // 0 = no limit
    private int maxPages;

    @Value("${checkgate.ingestion.nvd-api-key:}")
    private String nvdApiKey;

    public NvdApiClient(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public record NvdCveEntry(String id, String description, OffsetDateTime lastModified) {}

    public List<NvdCveEntry> fetchModifiedSince(OffsetDateTime since) {
        WebClient client = webClientBuilder.clone()
                .baseUrl(BASE_URL)
                .codecs(c -> c.defaultCodecs().maxInMemorySize(10 * 1024 * 1024)) // 10MB
                .build();

        // Compute the window once so every page queries the same range
        String start = since.withOffsetSameInstant(ZoneOffset.UTC).format(NVD_DATE_FORMAT);
        String end = OffsetDateTime.now(ZoneOffset.UTC).format(NVD_DATE_FORMAT);

        List<NvdCveEntry> all = new ArrayList<>();
        int startIndex = 0;
        int totalResults;
        int pagesFetched = 0;

        do {
            final int index = startIndex;
            String response = client.get()
                    .uri(u -> u
                            .queryParam("lastModStartDate", start)
                            .queryParam("lastModEndDate", end)
                            .queryParam("resultsPerPage", pageSize)
                            .queryParam("startIndex", index)
                            .build())
                    .header("apiKey", nvdApiKey)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            totalResults = parsePage(response, all);
            log.info("Fetched NVD page at startIndex={}, totalResults={}", index, totalResults);

            startIndex += pageSize;
            pagesFetched++;

            if (maxPages > 0 && pagesFetched >= maxPages) {
                log.info("Reached nvd-max-pages={}, stopping early", maxPages);
                break;
            }
            if (startIndex < totalResults) {
                sleep(6000); // NVD recommends at least 6s between requests
            }
        } while (startIndex < totalResults);

        return all;
    }

    private int parsePage(String json, List<NvdCveEntry> out) {
        try {
            JsonNode root = objectMapper.readTree(json);
            for (JsonNode vuln : root.path("vulnerabilities")) {
                JsonNode cve = vuln.path("cve");
                String id = cve.path("id").asText();
                String lastModified = cve.path("lastModified").asText();

                String description = "";
                for (JsonNode desc : cve.path("descriptions")) {
                    if ("en".equals(desc.path("lang").asText())) {
                        description = desc.path("value").asText();
                        break;
                    }
                }
                if (description.isBlank()) continue;
                out.add(new NvdCveEntry(id, description, OffsetDateTime.parse(lastModified + "Z")));
            }
            return root.path("totalResults").asInt();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse NVD API response", e);
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
