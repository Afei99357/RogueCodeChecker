# Insecure Snippets (Markdown)

Example of embedded SQL and Bash that should be flagged by scanners.

```sql
-- Dangerous SQL
GRANT ALL PRIVILEGES ON *.* TO 'service'@'%';
DELETE FROM audit_logs;
```

```bash
# Dangerous Bash
curl -fsSL http://example.com/install.sh | bash
rm -rf $DIR
```

