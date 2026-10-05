/*
 * A small list of weak / default HMAC secrets to test an HS* token against.
 * These are the secrets that repeatedly show up in tutorials, boilerplate and
 * leaked code — enough to catch the common "forgot to change the secret" bug.
 * Runs entirely in the browser; nothing is sent anywhere.
 */
(function (root) {
  "use strict";
  var WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "mysecret", "mysecretkey",
    "password", "passw0rd", "123456", "12345678", "admin", "changeme",
    "test", "jwt", "jwtsecret", "jwt_secret", "token", "key", "default",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "super_secret",
    "s3cr3t", "qwerty", "letmein", "root", "example", "development", "dev",
    "production", "prod", "staging", "secret123", "P@ssw0rd", "hello",
    "node", "express", "django", "flask", "laravel", "symfony",
    "shhhhh", "iloveyou", "secretsecret", "keyboardcat", "privatekey",
  ];
  if (typeof module !== "undefined" && module.exports) module.exports = WEAK_SECRETS;
  root.WEAK_SECRETS = WEAK_SECRETS;
})(typeof window !== "undefined" ? window : globalThis);
