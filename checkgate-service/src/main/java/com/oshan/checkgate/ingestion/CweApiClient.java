package com.oshan.checkgate.ingestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDate;
import java.util.*;

@Service
public class CweApiClient {

    private static final Logger log = LoggerFactory.getLogger(CweApiClient.class);
    private static final String BASE_URL = "https://cwe-api.mitre.org/api/v1";
    private static final int FETCH_BATCH = 25;

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public record CweVersion(String version, LocalDate date) {}

    public record CweEntry(String id, String name, String description) {
        public String embeddingText() {
            return name + ". " + description;
        }
    }

    public CweApiClient(WebClient.Builder webClientBuilder) {
        this.webClientBuilder = webClientBuilder;
    }

    public CweVersion fetchVersion() {
        JsonNode n = get("/cwe/version");
        return new CweVersion(n.path("ContentVersion").asText(),
                LocalDate.parse(n.path("ContentDate").asText()));
    }

    // No "list all" endpoint exists, so walk the descendants of each top-level
    // weakness in view 1000 (Research Concepts).
    public Set<String> fetchWeaknessIds() {
        Set<String> ids = new LinkedHashSet<>();
        for (JsonNode member : get("/cwe/view/1000").path("Views").path(0).path("Members")) {
            String rootId = member.hasNonNull("CweID")
                    ? member.get("CweID").asText()
                    : member.path("CWE_ID").asText();
            for (JsonNode node : get("/cwe/" + rootId + "/descendants?view=1000")) {
                collectIds(node, ids);
            }
            pause();
        }
        log.info("Found {} weakness IDs", ids.size());
        return ids;
    }

    public List<CweEntry> fetchJavaRelevant(Collection<String> ids) {
        List<String> all = new ArrayList<>(ids);
        List<CweEntry> out = new ArrayList<>();
        for (int i = 0; i < all.size(); i += FETCH_BATCH) {
            List<String> batch = all.subList(i, Math.min(i + FETCH_BATCH, all.size()));
            // Built as a plain string so the commas stay unencoded
            for (JsonNode w : get("/cwe/weakness/" + String.join(",", batch)).path("Weaknesses")) {
                if ("Deprecated".equals(w.path("Status").asText()) || !isJavaRelevant(w)) continue;
                String description = w.path("Description").asText();
                if (description.isBlank()) continue;
                out.add(new CweEntry("CWE-" + w.path("ID").asText(), w.path("Name").asText(), description));
            }
            pause();
        }
        log.info("Kept {} of {} weaknesses after the Java filter", out.size(), all.size());
        return out;
    }

    // Keep entries that name Java, are "Not Language-Specific", or list no language at all.
    // Other classes (Memory-Unsafe, Interpreted, ...) are not treated as language-neutral.
    private boolean isJavaRelevant(JsonNode weakness) {
        boolean anyLanguage = false;
        for (JsonNode p : weakness.path("ApplicablePlatforms")) {
            if (!"Language".equals(p.path("Type").asText())) continue;
            anyLanguage = true;
            if ("Java".equals(p.path("Name").asText())
                    || "Not Language-Specific".equals(p.path("Class").asText())) {
                return true;
            }
        }
        return !anyLanguage;
    }

    private void collectIds(JsonNode node, Set<String> ids) {
        ids.add(node.path("Data").path("ID").asText());
        for (JsonNode child : node.path("Children")) {
            collectIds(child, ids);
        }
    }

    private JsonNode get(String uri) {
        WebClient client = webClientBuilder.clone()
                .baseUrl(BASE_URL)
                .codecs(c -> c.defaultCodecs().maxInMemorySize(10 * 1024 * 1024))
                .build();
        String body = client.get().uri(uri).retrieve().bodyToMono(String.class).retry(2).block();
        try {
            return objectMapper.readTree(body);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CWE API response for " + uri, e);
        }
    }

    private void pause() {
        try {
            Thread.sleep(500); // MITRE documents no rate limit, so stay polite
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

}
