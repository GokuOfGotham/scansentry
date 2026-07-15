# Security Policy

## Reporting A Vulnerability

Please do not open a public issue for exploitable security problems.

Report security issues privately through GitHub's private vulnerability
reporting if it is available on this repository. If it is not available, contact
the maintainer directly through the GitHub account that owns the repository.

Include:

- Affected version or commit.
- Steps to reproduce.
- Expected and actual impact.
- Any logs, screenshots, or proof-of-concept details that help validate the
  issue safely.

## Supported Versions

Only the latest GitHub release is supported.

## Security Notes

ScanSentry performs local file and registry operations selected by the user.
The app should be run only from official GitHub releases and should not be run
with administrator privileges unless a specific remediation needs access to a
machine-wide registry key.
