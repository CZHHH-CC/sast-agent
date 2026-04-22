package com.example.search;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

/**
 * Safe counter-example. Uses parameterized queries throughout.
 * Scanner should NOT flag this file (it matches the "safe reverse"
 * of the SQL injection pattern).
 */
public class SafeUserDao {

    private final JdbcTemplate jdbcTemplate;

    public SafeUserDao(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> findByName(String name) {
        String sql = "SELECT id, name, email FROM users WHERE name = ?";
        return jdbcTemplate.queryForList(sql, new Object[]{name});
    }
}
