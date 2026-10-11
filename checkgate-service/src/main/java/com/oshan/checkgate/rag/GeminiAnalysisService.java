package com.oshan.checkgate.rag;

import com.google.common.collect.ImmutableMap;
import com.google.genai.Client;
import com.google.genai.types.*;
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
    
            Each line starts with its line number in the new file. Lines starting with "+" were added.
            Lines starting with "-" were removed, have no number, and must not be reported.
            reportedLine must be the number shown at the start of the vulnerable line.
    
            Code diff (line-annotated):
            %s
    
            Relevant CWE/CVE reference data:
            %s
            """.formatted(annotatedDiff, retrievedContext);
        return geminiClient.models.generateContent(ANALYSIS_MODEL, prompt, CONFIG);
    }

    public String describeForRetrieval(String annotatedDiff) {
        String prompt = """
            Decide whether this Java code performs any security-relevant operation: handling user or
            external input, file or network access, SQL or other queries, cryptography, authentication
            or credentials, secrets, deserialization, or process execution.

            If it clearly does none of these (for example pure arithmetic or simple getters), reply
            with exactly: NONE
            If you are unsure, do not reply NONE.

            Otherwise, in two sentences, describe the main security weakness using wording like a CWE
            entry (weakness name plus how it occurs). Do not mention variable names or line numbers.

            %s
            """.formatted(annotatedDiff);

        GenerateContentConfig cfg = GenerateContentConfig.builder()
                .temperature(0.0f)
                .thinkingConfig(ThinkingConfig.builder().thinkingBudget(256).build())
                .build();
        return geminiClient.models.generateContent(ANALYSIS_MODEL, prompt, cfg).text().strip();
    }
}
