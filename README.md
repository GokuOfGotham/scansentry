# ScanSentry

ScanSentry is a local, on-demand Windows utility for reviewing common cleanup
and security-risk areas: junk/cache files, startup entries, browser policy
hijacks, and executable file reputation.

It is not a real-time antivirus engine. Windows Security / Microsoft Defender
should remain enabled for real-time protection.

## Download

Download the latest installer from the official GitHub Releases page:

https://github.com/GokuOfGotham/scansentry/releases/latest

Current release: **v1.0.2**

## What It Does

- Scans temporary/cache locations for disposable files.
- Reviews common Windows startup locations.
- Checks browser homepage, search provider, startup URL, and managed-extension
  policy settings for Chrome, Edge, and Firefox.
- Hashes executable/script-like files in common user locations.
- Optionally checks file hashes against VirusTotal when the user supplies their
  own API key.
- Lets the user quarantine, delete, or ignore findings after review.

## Safety Model

- ScanSentry does not run as a background service.
- ScanSentry does not open inbound network ports.
- ScanSentry does not upload local files.
- VirusTotal integration sends only SHA-256 hashes, and only when the user
  configures an API key.
- File and registry actions are limited to findings produced by the current scan.
- Quarantine moves files into the app data folder with a randomized
  non-executable filename.

## Versions

- **v1.0.2**: Publisher-style app metadata changed to `GokuofGotham`; release
  includes SHA-256 checksums.
- **v1.0.1**: Electron/security hardening, dependency updates, public
  verification docs, and GitHub release trust signals.
- **v1.0.0**: Initial public Windows installer release.

## Verify A Release

Each GitHub release includes a Windows installer and SHA-256 checksum file.

On Windows, verify the installer hash with:

```powershell
Get-FileHash ".\ScanSentry.Setup.1.0.2.exe" -Algorithm SHA256
```

Compare the output with `SHA256SUMS.txt` attached to the same release.

## Windows SmartScreen

ScanSentry releases are currently unsigned. Windows may show an "Unknown
publisher" or Microsoft Defender SmartScreen warning for unsigned or uncommon
downloads.

Before running the installer:

1. Download only from the official GitHub release page.
2. Verify the SHA-256 checksum against `SHA256SUMS.txt`.
3. Confirm the file name matches the release, for example
   `ScanSentry.Setup.1.0.2.exe`.

If Windows SmartScreen appears after those checks, choose **More info**, then
**Run anyway**. If User Account Control appears, confirm the app name is
`ScanSentry`. The security publisher may still show as **Unknown publisher**
until a future release is digitally signed with a code-signing certificate.

Do not bypass Windows warnings for copies downloaded from mirrors, links in
messages, or any source other than this repository's official releases.

## Development

```powershell
npm install
npm run smoke
npm run dist
```

## Security

Please report security issues privately. See [SECURITY.md](SECURITY.md).
