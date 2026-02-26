# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of FastAPI RBAC Engine seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@kwantabit.com** with the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

We will acknowledge receipt of your vulnerability report within 48 hours and send you a more detailed response within 72 hours indicating the next steps in handling your report.

After the initial reply to your report, the security team will keep you informed of the progress towards a fix and full announcement, and may ask for additional information or guidance.

## Security Best Practices

When deploying FastAPI RBAC Engine in production:

1. **Always use HTTPS** - Never send credentials over unencrypted connections
2. **Change default secrets** - Use strong, unique JWT secrets
3. **Enable Redis authentication** - Set a strong password for Redis
4. **Use database connection pooling** - Configure appropriate pool sizes
5. **Enable audit logging** - Track all security-relevant events
6. **Set proper CORS policies** - Restrict allowed origins
7. **Keep dependencies updated** - Regularly update all packages
8. **Use environment variables** - Never hardcode secrets

## Disclosure Policy

When we receive a security bug report, we will:

1. Confirm the problem and determine the affected versions
2. Audit code to find any similar potential problems
3. Prepare fixes for all supported versions
4. Release new versions and update the public advisory

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or contact us at security@kwantabit.com.