package com.oshan.checkgate.github;

import org.springframework.stereotype.Service;

@Service
public class GitHubCommentService {

    // Posts the aggregated finding comment back to the pull request.
    public void postComment(String repoFullName, int prNumber, String commentBody) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

}
