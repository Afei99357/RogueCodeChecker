-- Dangerous SQL patterns that should trigger RogueCheck warnings
-- Should trigger: SQL001, SQL010, SQL020

-- SQL001_GRANT_ALL - Overly broad permissions
GRANT ALL PRIVILEGES ON *.* TO 'ai_service'@'%';
GRANT ALL ON database.* TO 'webapp'@'localhost';

-- SQL010_DROP_TABLE - Destructive operations
DROP TABLE user_sessions;
DROP TABLE IF EXISTS logs;  -- This might be acceptable
DROP TABLE temp_analysis_data;  -- This should trigger

-- SQL020_DELETE_NO_WHERE - Dangerous DELETE without WHERE
DELETE FROM user_activity_logs;
DELETE FROM temp_staging_table;

-- Additional dangerous patterns
TRUNCATE TABLE user_preferences;

-- Safe operations (should NOT trigger warnings)
DELETE FROM user_sessions WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
DROP TABLE IF EXISTS temp_processing_123;

GRANT SELECT ON analytics.user_metrics TO 'reporting_user'@'%';
GRANT INSERT, UPDATE ON warehouse.staging_table TO 'etl_service'@'10.0.%';
