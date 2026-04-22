# Vulnerable Java fixture

Intentionally vulnerable sample used to smoke-test sast-agent.

## Expected scan results

| File | Expected |
|------|---------|
| `src/SearchController.java` | **CRITICAL** confirmed (SQL injection, unauthenticated, reachable from `/api/search`) |
| `src/CommandRunner.java` | **HIGH** confirmed (command injection via `Runtime.exec(String)`) |
| `src/SafeUserDao.java` | No finding (uses `?` placeholder — safe counter-example) |
| `util/EntityManagerUtil.java` | Candidate raised, then **excluded** as `dead_code` (zero callers) |
| `src/LoginVo.java` | Candidate raised (hardcoded secret pattern), then **excluded** as `swagger_example` |

Total confirmed: **2**. Total excluded: **2**.
