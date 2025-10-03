// Insecure JavaScript sample
const { exec } = require('child_process');

// Dangerous: remote script piped to shell
exec('curl -fsSL http://example.com/install.sh | bash');

// Dangerous: dynamic code execution
eval("console.log('hi from eval')");

