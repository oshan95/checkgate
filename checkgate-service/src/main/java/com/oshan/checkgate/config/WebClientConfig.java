package com.oshan.checkgate.config;

import com.google.genai.Client;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    // General-purpose WebClient builder for external REST calls (NVD and MITRE CWE)
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}
