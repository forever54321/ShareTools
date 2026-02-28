# ShareTools

A single-file PowerShell GUI application for sharing folders and printers across your home network. No installation needed — just right-click and run.

## Features

**Host Mode** — run on the PC that has the files/printers:
- Enable network sharing services and firewall rules with one click
- Share folders with a folder browser and permission picker (Read Only / Read+Write)
- Share printers from a checklist of installed printers
- Remove shares easily
- Export a `ShareInfo.txt` file for clients to auto-detect your PC

**Client Mode** — run on PCs that want to connect:
- Connect to a host by name or IP (auto-detects `ShareInfo.txt` if present)
- Map network drives with drive letter picker and persistent option
- Connect to shared printers
- Disconnect drives and printers when done

## Requirements

- Windows 10 / 11
- PowerShell 5.1 (built into Windows)
- Administrator privileges (the script self-elevates)

## Usage

1. **Download** `ShareTools.ps1`
2. **Right-click** it and select **Run with PowerShell**
3. Choose **Host** or **Client** mode
4. Click the buttons — no typing commands needed

### Quick Start — Sharing Files

1. Open ShareTools on the host PC and click **Host**
2. Click **Setup Network** to enable sharing services
3. Click **Share Folders** to pick folders to share
4. Click **Export Info** to save `ShareInfo.txt`
5. Copy `ShareTools.ps1` and `ShareInfo.txt` to the client PC
6. Open ShareTools on the client PC and click **Client**
7. Click **Connect** (host auto-detected from `ShareInfo.txt`)
8. Click **Map Drives** to access shared folders

## Screenshot

The app uses a dark-themed Windows Forms GUI with a launch screen, host panel, and client panel — all navigated with clickable buttons.

## License

MIT
