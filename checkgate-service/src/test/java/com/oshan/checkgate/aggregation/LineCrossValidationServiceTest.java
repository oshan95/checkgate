package com.oshan.checkgate.aggregation;

import com.oshan.checkgate.model.VulnerabilityFinding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LineCrossValidationServiceTest {

    private final LineCrossValidationService service = new LineCrossValidationService();

    private static VulnerabilityFinding finding(int line, boolean lowConfidence) {
        return new VulnerabilityFinding("CWE-89", "HIGH", "reason", line, lowConfidence);
    }

    @Test
    void aLineInsideTheDiffIsKeptAsReported() {
        List<VulnerabilityFinding> result = service.validate(List.of(finding(6, false)), Set.of(5, 6, 7));
        assertFalse(result.get(0).lowConfidence());
    }

    @Test
    void aLineOutsideTheDiffIsFlaggedLowConfidence() {
        List<VulnerabilityFinding> result = service.validate(List.of(finding(6, false)), Set.of(10, 11));
        assertTrue(result.get(0).lowConfidence());
    }

    @Test
    void aFindingThatIsAlreadyLowConfidenceStaysLowConfidence() {
        List<VulnerabilityFinding> result = service.validate(List.of(finding(6, true)), Set.of(5, 6, 7));
        assertTrue(result.get(0).lowConfidence());
    }

    @Test
    void lineZeroIsNeverAVisibleLine() {
        List<VulnerabilityFinding> result = service.validate(List.of(finding(0, false)), Set.of(1, 2));
        assertTrue(result.get(0).lowConfidence());
    }

    @Test
    void everythingExceptTheFlagIsUnchanged() {
        VulnerabilityFinding out = service.validate(List.of(finding(6, false)), Set.of(10)).get(0);
        assertEquals("CWE-89", out.vulnerabilityType());
        assertEquals("HIGH", out.severity());
        assertEquals("reason", out.reasoning());
        assertEquals(6, out.reportedLine());
    }

    @Test
    void anEmptyListGivesAnEmptyList() {
        assertTrue(service.validate(List.of(), Set.of(1)).isEmpty());
    }

    @Test
    void eachFindingIsCheckedOnItsOwn() {
        List<VulnerabilityFinding> result = service.validate(List.of(finding(3, false), finding(9, false)), Set.of(3));
        assertFalse(result.get(0).lowConfidence());
        assertTrue(result.get(1).lowConfidence());
    }

    @Test
    void isLineWithinDiffReflectsTheVisibleLines() {
        assertTrue(service.isLineWithinDiff(4, Set.of(4, 5)));
        assertFalse(service.isLineWithinDiff(6, Set.of(4, 5)));
    }
}
