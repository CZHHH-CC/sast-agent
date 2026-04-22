package com.example.search;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

/**
 * Search API. The endpoint /api/search is registered under the permitAll()
 * whitelist in SecurityConfig, so it's reachable without authentication.
 */
@RestController
public class SearchController {

    private final JdbcTemplate jdbcTemplate;

    public SearchController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/api/search")
    public List<Map<String, Object>> search(@RequestParam String keyword) {
        // VULN: string concatenation straight into SQL, no parameterization.
        String sql = "SELECT id, name, email FROM users WHERE name LIKE '%" + keyword + "%'";
        return jdbcTemplate.queryForList(sql);
    }
}
