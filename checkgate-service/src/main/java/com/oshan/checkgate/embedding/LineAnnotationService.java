package com.oshan.checkgate.embedding;

import com.oshan.checkgate.model.AnnotatedDiff;
import com.oshan.checkgate.model.FileDiff;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class LineAnnotationService {
    private static final Pattern HUNK = Pattern.compile("^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@.*");

    // Numbers every visible line with its line number in the NEW file, taken from the hunk headers.
    // Removed lines are shown without a number so they cannot be reported.
    public AnnotatedDiff annotate(FileDiff file) {
        StringBuilder sb = new StringBuilder();
        Set<Integer> added = new TreeSet<>();
        Set<Integer> visible = new TreeSet<>();
        int newLine = 0;
        boolean inHunk = false;

        for (String raw : file.diffContent().split("\n")) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            Matcher m = HUNK.matcher(line);
            if (m.matches()) {
                newLine = Integer.parseInt(m.group(1));
                inHunk = true;
                sb.append("...\n");
                continue;
            }
            if (!inHunk || line.startsWith("\\")) continue; // file headers, "No newline" markers

            if (line.startsWith("-")) {
                sb.append("    ").append(line).append('\n');
            } else {
                if (line.startsWith("+")) added.add(newLine);
                visible.add(newLine);
                sb.append(newLine).append(": ").append(line).append('\n');
                newLine++;
            }
        }
        return new AnnotatedDiff(file.filePath(), sb.toString(), added, visible);
    }
}
