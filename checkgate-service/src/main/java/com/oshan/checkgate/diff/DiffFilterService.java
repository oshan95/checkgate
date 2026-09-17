package com.oshan.checkgate.diff;

import org.springframework.stereotype.Service;

@Service
public class DiffFilterService {
    // Skips lockfiles, generated code, vendor dependencies, formatting-only changes.
    // TODO: implement file filtering logic.
    public boolean shouldScan(String filePath) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
