package com.oshan.checkgate.github;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Service
public class GitHubCommentService {

    private final WebClient githubWebClient;

    public GitHubCommentService(@Qualifier("githubWebClient") WebClient githubWebClient) {
        this.githubWebClient = githubWebClient;
    }

    // Posts the aggregated finding comment back to the pull request.
    public void postComment(String repoOwner, String repoName, int issueOrPrNumber, String commentBody) {
        githubWebClient.post()
                .uri("/repos/{owner}/{repo}/issues/{number}/comments", repoOwner, repoName, issueOrPrNumber)
                .bodyValue(Map.of("body", commentBody))
                .retrieve()
                .toBodilessEntity()
                .block();
    }

}
