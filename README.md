# Atomic Maestro

## Overview
**Atomic Maestro** is a streamlined CLI tool designed to bridge the automation gap between Cyber Threat Intelligence (CTI) and Red Canary's Atomic Red Team Atomic Runner functionality. 

It takes MITRE ATT&CK® Navigator JSON layers and dynamically orchestrates them into execution-ready CSV schedules for [Atomic Red Team's](https://github.com/redcanaryco/atomic-red-team) Atomic Runner. Perfect for SOC teams, Detection Engineers, and Red Teamers validating SIEM platforms against specific threat actors or specific campaigns.

## Features
* **Tactical Sequencing:** Automatically sorts MITRE techniques based on the logical attack kill chain (from *Reconnaissance* down to *Impact*).
* **Platform Filtering:** Target specific environments (e.g., Windows, Azure AD, Linux) to ensure your schedules only run relevant atomic tests.
* **Custom Timeouts:** Dynamically control the maximum execution time for tests directly via CLI.
* **Seamless Integration:** Directly parses JSON files exported from the MITRE ATT&CK Navigator.
* **Runner-Ready:** Generates correctly formatted `.csv` files required by the Atomic Runner.

## Quick Start

### Prerequisites
* Python 3.x (No external libraries required)
* Atomic Red Team Execution Framework and Atomics Folder installed
* A valid Atomic Red Team source schedule CSV.

### Basic Usage
To generate a complete emulation plan (e.g., for APT29):

`python atomic_maestro.py --mitre-filepath 'C:\Users\johndoe\apt29_layer.json'`

### Advanced Usage (Platform Filtering & Timeouts)
To generate an emulation plan specifically for Windows and Azure AD, with a 120-second timeout:

`python atomic_maestro.py --mitre-filepath 'C:\Users\johndoe\apt29_layer.json' --source-filepath C:\Users\johndoe\AtomicRunner\AtomicRunnerSchedule.csv --destination-filepath APT29_emulation_plan.csv --supported-platforms windows azure-ad --timeout-seconds 120`

### Arguments

| Argument | Required | Description | Default |
| :--- | :---: | :--- | :--- |
| --mitre-filepath | ✅ | Path to your MITRE ATT&CK® Navigator JSON file. | None |
| --source-filepath | ❌ | Path to the base Atomic Red Team schedule CSV. | ~/AtomicRunner/AtomicRunnerSchedule.csv |
| --destination-filepath| ❌ | Path where the generated emulation schedule will be saved. | ~/AtomicRunner/atomic_schedule.csv |
| --timeout-seconds | ❌ | Maximum execution time (in seconds) for each atomic test. | 60 |
| --supported-platforms | ❌ | Filter techniques by platform (space-separated). Example: windows azure-ad office365 | None (All platforms) |

## Example Workflow: Targeted APT29 Emulation
1. Generate the base CSV schedule with `Invoke-GenerateNewSchedule` or refresh it with `Invoke-RefreshExistingSchedule` if has not been done previously.
2. Go to the MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/)
3. Create or open an existing layer with the desired techniques associated with APT29 scored as 1.
4. Export the layer as a JSON file (apt29_layer.json).
5. Run the Maestro to build a Windows-only attack path:
   
   `python atomic_maestro.py --mitre-filepath C:\Users\johndoe\Desktop\apt29_layer.json --source-filepath C:\Users\johndoe\AtomicRunner\AtomicRunnerSchedule.csv --destination-filepath APT29_emulation_plan.csv --supported-platforms windows --timeout-seconds 60`
   
6. Feed the generated atomic_schedule.csv into your Atomic Runner and validate your SIEM detections!