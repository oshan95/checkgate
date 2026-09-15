package com.oshan.checkgate.rag;

import com.google.genai.Client;
import com.google.genai.types.GenerateContentResponse;

public class GeminiAnalysisService {
    private static final String ANALYSIS_MODEL = "gemini-2.5-flash";

    private final Client geminiClient;

    public GeminiAnalysisService(Client geminiClient) {
        this.geminiClient = geminiClient;
    }

    // Sends the diff plus retrieved CWE/CVE context to Gemini, requesting structured output
    // (vulnerability type, severity, reasoning).
    // TODO: configure structured/JSON output via GenerateContentConfig
    public GenerateContentResponse analyze(String annotatedDiff, String retrievedContext) {
        String prompt = "Code diff:\n" + annotatedDiff + "\n\nRelevant CWE/CVE reference data:\n" + retrievedContext;
        return geminiClient.models.generateContent(ANALYSIS_MODEL, prompt, null);
    }
}
