package com.oshan.checkgate.diff;

import com.oshan.checkgate.model.FileDiff;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.regex.Pattern;

@Service
public class DiffFilterService {
    // Skips lockfiles, generated code, vendor dependencies, formatting-only changes.

    private static final List<String> SKIP_PATH_PATTERNS = List.of(
            ".*/pom\\.xml$",
            ".*package-lock\\.json$",
            ".*yarn\\.lock$",
            ".*\\.lock$",
            ".*/target/.*",
            ".*/build/.*",
            ".*/node_modules/.*",
            ".*/vendor/.*",
            ".*/generated/.*",
            ".*\\.g\\.java$"
    );
    public boolean shouldScan(FileDiff fileDiff) {
        if (isSkippedPath(fileDiff.filePath())) {
            return false;
        }
        return !isFormattingOnly(fileDiff.diffContent());
    }

    private boolean isSkippedPath(String path) {
        return SKIP_PATH_PATTERNS.stream()
                .anyMatch(pattern -> Pattern.matches(pattern, path));
    }

    private boolean isFormattingOnly(String diffContent) {
        for (String line : diffContent.split("\n")) {
            if (line.startsWith("+++") || line.startsWith("---")) continue;
            if (line.startsWith("+") || line.startsWith("-")) {
                String normalized = line.substring(1).strip();
                // Strip whitespace from each changed line and see what's left.
                // If any line still has real content after stripping, this is a genuine code change.
                // If every changed line strips down to nothing, the whole diff is just whitespace or formatting, and gets skipped.
                if (!normalized.isEmpty()) {
                    return false;
                }
            }
        }
        return true;
    }
}
