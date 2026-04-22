package com.example.util;

import javax.persistence.EntityManager;
import java.util.List;

/**
 * DEAD CODE. This class has SQL injection sinks but no one in the repo
 * imports it or calls its methods. Scanner will flag it; Validator must
 * exclude as `dead_code` after verifying zero callers.
 *
 * Verification steps Validator should perform:
 *   grep -r "EntityManagerUtil" --include="*.java"   → only the file itself
 *   grep -r "import .*EntityManagerUtil"              → empty
 *   grep -r "new EntityManagerUtil"                   → empty
 */
public class EntityManagerUtil {

    private final EntityManager em;

    public EntityManagerUtil(EntityManager em) { this.em = em; }

    @SuppressWarnings("unchecked")
    public List<Object> findAllFromTable(String tableName) {
        // Would be a SQL injection if it were ever called.
        String sql = "SELECT * FROM " + tableName;
        return em.createNativeQuery(sql).getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Object> searchByColumn(String column, String value) {
        String sql = "SELECT * FROM users WHERE " + column + " = '" + value + "'";
        return em.createNativeQuery(sql).getResultList();
    }
}
