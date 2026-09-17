package com.oshan.checkgate.aggregation;

import com.oshan.checkgate.model.VulnerabilityFinding;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ResultAggregationService {

    // Aggregates findings across all scanned files into one PR comment.
    // TODO: implement aggregation and comment formatting.
    public String buildPrComment(List<VulnerabilityFinding> findings) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

}
