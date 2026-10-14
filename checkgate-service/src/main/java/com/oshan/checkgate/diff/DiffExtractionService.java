package com.oshan.checkgate.diff;

import com.oshan.checkgate.model.FileDiff;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DiffExtractionService {
    // Extracts the code diff from an incoming PR
    public List<FileDiff> extractDiff(String rawDiff) {
        List<FileDiff> files = new ArrayList<>();
        String[] parts = rawDiff.split("(?=diff --git)");

        for (String part : parts) {
            if (part.isBlank()) continue;
            String filePath = extractFilePath(part);
            if (filePath != null) {
                files.add(new FileDiff(filePath, part));
            }
        }
        return files;
    }

    private String extractFilePath(String diffBlock) {
        for (String line : diffBlock.split("\n")) {
            if (line.startsWith("+++ b/")) {
                return line.substring(6);
            }
        }
        return null;
    }
}
