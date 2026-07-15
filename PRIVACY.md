# Privacy

ScanSentry is designed to run locally.

## Local Data

The app stores settings and quarantine metadata in the Electron app data folder
for the current Windows user. This can include:

- VirusTotal API key, if supplied by the user.
- Extra scan paths and exclusions.
- Last scan timestamp.
- Quarantine manifest entries for files or registry values moved into
  quarantine.

## Network Use

ScanSentry does not upload local files.

If the user configures a VirusTotal API key, ScanSentry sends SHA-256 file hashes
to VirusTotal's file lookup API to check reputation. The app does not send the
file contents.

No inbound network service is opened by the app.

## Deleting Data

Quarantined files can be restored or permanently deleted in the app. Settings
and quarantine metadata are stored under the current user's application data
folder and can be removed by uninstalling the app and deleting its user data.
