# ScanSentry

ScanSentry is a local, on-demand Windows scan utility for reviewing junk files,
startup entries, browser policy hijacks, and executable file reputation.

It is not a real-time antivirus engine. Windows Security / Microsoft Defender
should remain enabled for real-time protection.

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

## Verify A Release

Each GitHub release includes a Windows installer and SHA-256 checksum file.

On Windows, verify the installer hash with:

```powershell
Get-FileHash ".\ScanSentry.Setup.1.0.1.exe" -Algorithm SHA256
```

Compare the output with `SHA256SUMS.txt` attached to the same release.

## Windows SmartScreen

ScanSentry releases are currently unsigned. Windows may show an "Unknown
publisher" or Microsoft Defender SmartScreen warning for unsigned or uncommon
downloads.

Code signing is planned. Until then, download only from the official GitHub
releases page and verify the SHA-256 checksum before running the installer.

## Development

```powershell
npm install
npm run smoke
npm run dist
```

## Security

Please report security issues privately. See [SECURITY.md](SECURITY.md).
