package com.oshan.checkgate.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class NvdApiClient {
    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final DateTimeFormatter NVD_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${checkgate.ingestion.nvd-api-key:}")
    private String nvdApiKey;

    public NvdApiClient(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public record NvdCveEntry(String id, String description, OffsetDateTime lastModified) {}

    public List<NvdCveEntry> fetchModifiedSince(OffsetDateTime since) {
        WebClient client = webClientBuilder.baseUrl(BASE_URL).build();

        String response = client.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("lastModStartDate", since.format(NVD_DATE_FORMAT))
                        .queryParam("lastModEndDate", OffsetDateTime.now().format(NVD_DATE_FORMAT))
                        .queryParam("resultsPerPage", 200)
                        .build())
                .header("apiKey", nvdApiKey)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        return parseResponse(response);
    }

    private List<NvdCveEntry> parseResponse(String json) {
        List<NvdCveEntry> entries = new ArrayList<>();
        try {
            JsonNode vulnerabilities = objectMapper.readTree(json).path("vulnerabilities");
            for (JsonNode vuln : vulnerabilities) {
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
                entries.add(new NvdCveEntry(id, description, OffsetDateTime.parse(lastModified + "Z")));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse NVD API response", e);
        }
        return entries;
    }
}
