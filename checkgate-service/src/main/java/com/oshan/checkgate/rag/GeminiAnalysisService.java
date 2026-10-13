package com.oshan.checkgate.rag;

import com.google.common.collect.ImmutableMap;
import com.google.genai.Client;
import com.google.genai.types.*;
import com.oshan.checkgate.config.GeminiRetry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class GeminiAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(GeminiAnalysisService.class);

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

    private final Client geminiClient;
    private final String model;
    private final GenerateContentConfig analysisConfig;
    private final GenerateContentConfig retrievalConfig;
    private final GeminiRetry retry;



    public GeminiAnalysisService(Client geminiClient,
                                 @Value("${gemini.model}") String model,
                                 @Value("${gemini.retrieval-thinking-level:MEDIUM}") String retrievalLevel,
                                 @Value("${gemini.analysis-thinking-level:LOW}") String analysisLevel,
                                 GeminiRetry retry) {
        this.geminiClient = geminiClient;
        this.model = model;

        ThinkingLevel.Known retrieval = ThinkingLevel.Known.valueOf(retrievalLevel.trim().toUpperCase());
        ThinkingLevel.Known analysis = ThinkingLevel.Known.valueOf(analysisLevel.trim().toUpperCase());

        this.retrievalConfig = GenerateContentConfig.builder()
                .thinkingConfig(ThinkingConfig.builder().thinkingLevel(retrieval).build())
                .build();
        this.analysisConfig = GenerateContentConfig.builder()
                .responseMimeType("application/json")
                .responseSchema(FINDING_SCHEMA)
                .thinkingConfig(ThinkingConfig.builder().thinkingLevel(analysis).build())
                .build();

        this.retry = retry;

        // Logged once at startup so every evaluation run records its exact settings
        log.info("Gemini settings: model={}, retrieval thinking={}, analysis thinking={}",
                model, retrieval, analysis);
    }

    // Retrieval query step: turns code into CWE-style prose so it can be matched against CWE text
    public String describeForRetrieval(String annotatedDiff) {
        String prompt = """
                Decide whether this Java code performs any security-relevant operation: handling user or
                external input, file or network access, SQL or other queries, cryptography, authentication
                or credentials, secrets, deserialisation, or process execution.

                If it clearly does none of these (for example pure arithmetic or simple getters), reply
                with exactly: NONE
                If you are unsure, do not reply NONE.

                Otherwise, in two sentences, describe the main security weakness using wording like a CWE
                entry (weakness name plus how it occurs). Do not mention variable names or line numbers.

                %s
                """.formatted(annotatedDiff);
        return retry.call("retrieval description",
                () -> geminiClient.models.generateContent(model, prompt, retrievalConfig).text().strip());
    }

    // Sends the diff plus retrieved CWE/CVE context to Gemini, requesting structured output.
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
        return retry.call("analysis",
                () -> geminiClient.models.generateContent(model, prompt, analysisConfig));
    }
}
