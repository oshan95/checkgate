package com.oshan.checkgate.diff;

import com.oshan.checkgate.model.FileDiff;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GuardRailService {
    @Value("${checkgate.scan.max-files:50}")
    private int maxFiles;

    @Value("${checkgate.scan.max-diff-lines:1000}")
    private int maxDiffLines;

    public boolean exceedsSizeLimit(List<FileDiff> files) {
        if (files.size() > maxFiles) {
            return true;
        }
        int totalLines = files.stream()
                .mapToInt(f -> countChangedLines(f.diffContent()))
                .sum();
        return totalLines > maxDiffLines;
    }

    private int countChangedLines(String diffContent) {
        int count = 0;
        for (String line : diffContent.split("\n")) {
            if ((line.startsWith("+") && !line.startsWith("+++"))
                    || (line.startsWith("-") && !line.startsWith("---"))) {
                count++;
            }
        }
        return count;
    }
}
