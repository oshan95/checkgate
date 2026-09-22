package com.oshan.checkgate.rag;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.genai.types.GenerateContentResponse;
import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GeminiResponseParser {

    private record RawFinding(String vulnerabilityType, String severity, String reasoning, int reportedLine) {}

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<VulnerabilityFinding> parse(GenerateContentResponse response) throws Exception {
        RawFinding[] raw = objectMapper.readValue(response.text(), RawFinding[].class);
        return List.of(raw).stream()
                .map(r -> new VulnerabilityFinding(
                        r.vulnerabilityType(), r.severity(), r.reasoning(), r.reportedLine(), false))
                .toList();
    }

}
