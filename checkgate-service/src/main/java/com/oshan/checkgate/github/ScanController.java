package com.oshan.checkgate.github;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class ScanController {

    //Receives the scan request triggered by the GitHub Actions workflow
    @PostMapping("/scan")
    public String triggerScan(@RequestBody String prPayload) {
        throw new UnsupportedOperationException("Not yet implemented");
    }

}
