# RogueCheck Report

## [HIGH] SQL_STRICT_GRANT_ALL — dangerous_sql.sql:5
Broad GRANT ALL detected.

```
        3: 
        4: -- SQL001_GRANT_ALL - Overly broad permissions
-->     5: GRANT ALL PRIVILEGES ON *.* TO 'ai_service'@'%';
        6: GRANT ALL ON database.* TO 'webapp'@'localhost';
        7: 
```
**Fix:** Use least-privilege GRANTs on specific objects.

## [HIGH] SQL_STRICT_GRANT_ALL — dangerous_sql.sql:6
Broad GRANT ALL detected.

```
        4: -- SQL001_GRANT_ALL - Overly broad permissions
        5: GRANT ALL PRIVILEGES ON *.* TO 'ai_service'@'%';
-->     6: GRANT ALL ON database.* TO 'webapp'@'localhost';
        7: 
        8: -- SQL010_DROP_TABLE - Destructive operations
```
**Fix:** Use least-privilege GRANTs on specific objects.

## [MEDIUM] SQL_STRICT_DROP_TABLE — dangerous_sql.sql:9
Potential destructive DROP TABLE.

```
        7: 
        8: -- SQL010_DROP_TABLE - Destructive operations
-->     9: DROP TABLE user_sessions;
       10: DROP TABLE IF EXISTS logs;  -- This might be acceptable
       11: DROP TABLE temp_analysis_data;  -- This should trigger
```
**Fix:** Avoid DROP outside migrations/tests or guard with IF EXISTS and temp scope.

## [MEDIUM] SQL_STRICT_DROP_TABLE — dangerous_sql.sql:10
Potential destructive DROP TABLE.

```
        8: -- SQL010_DROP_TABLE - Destructive operations
        9: DROP TABLE user_sessions;
-->    10: DROP TABLE IF EXISTS logs;  -- This might be acceptable
       11: DROP TABLE temp_analysis_data;  -- This should trigger
       12: 
```
**Fix:** Avoid DROP outside migrations/tests or guard with IF EXISTS and temp scope.

## [MEDIUM] SQL_STRICT_DROP_TABLE — dangerous_sql.sql:11
Potential destructive DROP TABLE.

```
        9: DROP TABLE user_sessions;
       10: DROP TABLE IF EXISTS logs;  -- This might be acceptable
-->    11: DROP TABLE temp_analysis_data;  -- This should trigger
       12: 
       13: -- SQL020_DELETE_NO_WHERE - Dangerous DELETE without WHERE
```
**Fix:** Avoid DROP outside migrations/tests or guard with IF EXISTS and temp scope.

## [HIGH] SQL_STRICT_DELETE_ALL — dangerous_sql.sql:14
DELETE statement without WHERE clause.

```
       12: 
       13: -- SQL020_DELETE_NO_WHERE - Dangerous DELETE without WHERE
-->    14: DELETE FROM user_activity_logs;
       15: DELETE FROM temp_staging_table;
       16: 
```
**Fix:** Add a WHERE clause or guard with partition predicates.

## [HIGH] SQL_STRICT_DELETE_ALL — dangerous_sql.sql:15
DELETE statement without WHERE clause.

```
       13: -- SQL020_DELETE_NO_WHERE - Dangerous DELETE without WHERE
       14: DELETE FROM user_activity_logs;
-->    15: DELETE FROM temp_staging_table;
       16: 
       17: -- Additional dangerous patterns
```
**Fix:** Add a WHERE clause or guard with partition predicates.
