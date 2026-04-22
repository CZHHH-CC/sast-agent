package com.example.search;

import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
public class CommandRunner {

    /**
     * Admin-only ping utility. Reachable at POST /api/admin/ping behind the
     * hasRole('ADMIN') guard — but the command assembly is vulnerable once
     * an admin (or compromised admin session) hits it.
     */
    @PostMapping("/api/admin/ping")
    public String ping(@RequestParam String host) throws Exception {
        // VULN: single-string Runtime.exec passes through a shell on many
        // platforms and concatenates user input. ";rm -rf /" would be parsed.
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }
}
