package com.oshan.checkgate.rag;

import com.google.common.collect.ImmutableMap;
import com.google.genai.Client;
import com.google.genai.types.GenerateContentConfig;
import com.google.genai.types.GenerateContentResponse;
import com.google.genai.types.Schema;
import com.google.genai.types.Type;
import org.springframework.stereotype.Service;

@Service
public class GeminiAnalysisService {
    private static final String ANALYSIS_MODEL = "gemini-2.5-flash";

    private final Client geminiClient;

    public GeminiAnalysisService(Client geminiClient) {
        this.geminiClient = geminiClient;
    }

    private static final Schema FINDING_SCHEMA =
            Schema.builder()
                    .type(Type.Known.ARRAY)
                    .items(
                            Schema.builder()
                                    .type(Type.Known.OBJECT)
                                    .properties(
                                            ImmutableMap.of(
                                                    "vulnerabilityType", Schema.builder().type(Type.Known.STRING).build(),
                                                    "severity", Schema.builder().type(Type.Known.STRING).build(),
                                                    "reasoning", Schema.builder().type(Type.Known.STRING).build(),
                                                    "reportedLine", Schema.builder().type(Type.Known.INTEGER).build()
                                            ))
                                    .required("vulnerabilityType", "severity", "reasoning", "reportedLine"))
                    .build();

    private static final GenerateContentConfig CONFIG =
            GenerateContentConfig.builder()
                    .responseMimeType("application/json")
                    .responseSchema(FINDING_SCHEMA)
                    .build();


    // Sends the diff plus retrieved CWE/CVE context to Gemini, requesting structured output (vulnerability type, severity, reasoning).
    public GenerateContentResponse analyze(String annotatedDiff, String retrievedContext) {
        String prompt = """
                You are a security code reviewer. Analyse the following Java code diff for vulnerabilities.
                Only report genuine security issues, not style or formatting concerns.
                If no vulnerabilities are found, return an empty array.

                Code diff (line-annotated):
                %s

                Relevant CWE/CVE reference data:
                %s
                """.formatted(annotatedDiff, retrievedContext);
        return geminiClient.models.generateContent(ANALYSIS_MODEL, prompt, CONFIG);
    }
}
