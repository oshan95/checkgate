package com.oshan.checkgate.embedding;

import com.oshan.checkgate.model.AnnotatedDiff;
import com.oshan.checkgate.model.FileDiff;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Plain unit tests: no Spring context, no database, no network.
class LineAnnotationServiceTest {

    private final LineAnnotationService service = new LineAnnotationService();

    private static FileDiff diff(String... lines) {
        return new FileDiff("A.java", String.join("\n", lines));
    }

    @Test
    void numbersAddedAndContextLinesFromTheHunkHeader() {
        AnnotatedDiff a = service.annotate(diff("@@ -5,2 +5,3 @@", " keep", "+added", " keep2"));
        assertEquals(Set.of(6), a.addedLines());
        assertEquals(Set.of(5, 6, 7), a.visibleLines());
        assertTrue(a.annotatedText().contains("6: +added"));
    }

    @Test
    void removedLinesHaveNoNumberAndDoNotShiftTheNumbering() {
        AnnotatedDiff a = service.annotate(diff("@@ -10,3 +10,3 @@", " before", "-old", "+new", " after"));
        assertEquals(Set.of(11), a.addedLines());
        assertEquals(Set.of(10, 11, 12), a.visibleLines());
        assertTrue(a.annotatedText().contains("    -old"));
        assertFalse(a.annotatedText().contains(": -old"));
    }

    @Test
    void severalRemovedLinesBeforeAnAddedLineStillGiveTheRightNumber() {
        AnnotatedDiff a = service.annotate(diff("@@ -1,4 +1,2 @@", "-a", "-b", " c", "+d"));
        assertEquals(Set.of(2), a.addedLines());
        assertEquals(Set.of(1, 2), a.visibleLines());
    }

    @Test
    void eachHunkRestartsFromItsOwnHeader() {
        AnnotatedDiff a = service.annotate(diff("@@ -1,1 +1,1 @@", " x", "@@ -40,1 +50,2 @@", " y", "+z"));
        assertEquals(Set.of(51), a.addedLines());
        assertEquals(Set.of(1, 50, 51), a.visibleLines());
    }

    @Test
    void fileHeadersBeforeTheFirstHunkAreNotNumbered() {
        AnnotatedDiff a = service.annotate(diff("diff --git a/A.java b/A.java", "--- a/A.java", "+++ b/A.java",
                "@@ -1,1 +1,2 @@", " x", "+y"));
        assertEquals(Set.of(2), a.addedLines());
        assertFalse(a.annotatedText().contains("+++ b/A.java"));
    }

    @Test
    void noNewlineMarkersAreIgnored() {
        AnnotatedDiff a = service.annotate(diff("@@ -1,1 +1,2 @@", " x", "+y", "\\ No newline at end of file"));
        assertEquals(Set.of(1, 2), a.visibleLines());
    }

    @Test
    void windowsLineEndingsGiveTheSameResult() {
        AnnotatedDiff a = service.annotate(new FileDiff("A.java", "@@ -1,1 +1,2 @@\r\n x\r\n+y"));
        assertEquals(Set.of(2), a.addedLines());
        assertEquals(Set.of(1, 2), a.visibleLines());
    }

    @Test
    void aHeaderWithTrailingContextTextIsStillRecognised() {
        AnnotatedDiff a = service.annotate(diff("@@ -3,2 +3,2 @@ public void foo()", " x", "+y"));
        assertEquals(Set.of(4), a.addedLines());
    }

    @Test
    void aNewFileDiffNumbersEveryLineFromOne() {
        AnnotatedDiff a = service.annotate(diff("@@ -0,0 +1,3 @@", "+a", "+b", "+c"));
        assertEquals(Set.of(1, 2, 3), a.addedLines());
    }

    @Test
    void aDiffThatOnlyRemovesLinesHasNothingToReport() {
        AnnotatedDiff a = service.annotate(diff("@@ -1,2 +0,0 @@", "-a", "-b"));
        assertTrue(a.addedLines().isEmpty());
        assertTrue(a.visibleLines().isEmpty());
    }
}
