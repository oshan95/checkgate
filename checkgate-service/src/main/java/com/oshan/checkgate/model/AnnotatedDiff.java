package com.oshan.checkgate.model;

import java.util.Set;

public record AnnotatedDiff(String filePath, String annotatedText, Set<Integer> addedLines
        , Set<Integer> visibleLines) {
}
