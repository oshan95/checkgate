package com.oshan.checkgate.aggregation;

import org.springframework.stereotype.Service;

@Service
public class LineCrossValidationService {

    // Flags any reported line number outside the range as low-confidence.
    // TODO: implement cross-validation against diff-native line numbers.
    public boolean isLineWithinDiffRange(int reportedLine, int diffStartLine, int diffEndLine) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

}
