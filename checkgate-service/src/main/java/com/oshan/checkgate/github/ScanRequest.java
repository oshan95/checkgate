package com.oshan.checkgate.github;

public record ScanRequest (String repoOwner, String repoName, int prNumber, String diff) { }
