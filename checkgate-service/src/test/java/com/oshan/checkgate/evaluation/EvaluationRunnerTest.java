package com.oshan.checkgate.evaluation;

import com.oshan.checkgate.embedding.LineAnnotationService;
import com.oshan.checkgate.model.AnnotatedDiff;
import com.oshan.checkgate.model.FileDiff;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Tests the function-to-diff wrapper that the evaluation relies on. No Spring, no network.
class EvaluationRunnerTest {

    @Test
    void wrapsAFunctionAsANewFileDiff() {
        String diff = EvaluationRunner.toNewFileDiff("src/A.java", "int f() {\n  return 1;\n}");
        assertEquals("diff --git a/src/A.java b/src/A.java\n"
                + "new file mode 100644\n"
                + "--- /dev/null\n"
                + "+++ b/src/A.java\n"
                + "@@ -0,0 +1,3 @@\n"
                + "+int f() {\n"
                + "+  return 1;\n"
                + "+}\n", diff);
    }

    @Test
    void aTrailingNewlineIsNotCountedAsAnotherLine() {
        assertTrue(EvaluationRunner.toNewFileDiff("A.java", "a\nb\n").contains("@@ -0,0 +1,2 @@"));
    }

    @Test
    void windowsLineEndingsAreNormalised() {
        assertFalse(EvaluationRunner.toNewFileDiff("A.java", "a\r\nb").contains("\r"));
    }

    @Test
    void reportedLinesMatchTheFunctionRelativeLabels() {
        // Line 1 of the function must be line 1 for the pipeline, so a reported line can be compared with a label directly.
        String code = "void run(String user) {\n  query(\"SELECT \" + user);\n}";
        AnnotatedDiff annotated = new LineAnnotationService().annotate(new FileDiff("A.java", EvaluationRunner.toNewFileDiff("A.java", code)));
        assertEquals(Set.of(1, 2, 3), annotated.addedLines());
        assertTrue(annotated.annotatedText().contains("2: +  query(\"SELECT \" + user);"));
    }
}
