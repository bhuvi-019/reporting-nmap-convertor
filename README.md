# Nmap XML to Excel Report Converter

Convert one or more Nmap XML reports into an Excel workbook with `Summary`, `Hosts`, and `Results` worksheets. When using `--combine-dir`, the tool also writes a combined XML file.

## Features

- Processes one or multiple Nmap XML reports.
- Creates summary, host inventory, and service/script result worksheets.
- Preserves the source scan name on host and result rows for traceability.
- Preserves duplicate host observations across reports rather than merging solely by IP address.
- Validates XML before parsing and reports the input file when parsing fails.
- Writes text values as Excel strings to reduce formula-injection risk.
- Includes filters, frozen headers, and readable column widths.

## Requirements

- Python 3.9 or newer
- Nmap XML output files (generate with Nmap's `-oX` option)

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Convert a single report:

```bash
python nmap_report_converter.py -o report.xlsx scan.xml
```

Convert several reports:

```bash
python nmap_report_converter.py -o report.xlsx scan1.xml scan2.xml
```

Process all XML files in a directory and also create a combined XML file:

```bash
python nmap_report_converter.py --combine-dir ./nmap-xml -o combined-report.xlsx
```

The directory mode writes `combined-report.xlsx` and `combined-report.xml`.

## Duplicate handling

The Excel workbook retains each report's observations and includes the source scan filename. If the same IP appears in multiple reports, each scan's records remain available. This is intentional: port states, service versions, hostnames, and scan times can differ.

The combined XML also preserves host entries from all input reports. It does not deduplicate or merge hosts by IP. The combined XML retains root-level metadata from the first input report, so use the individual input XML files as the authoritative source for each scan's original metadata.

## Output worksheets

- **Summary**: source filename, command, Nmap version, scan type, timestamps, and host counts.
- **Hosts**: source scan, hostname, IP, status, service count, and OS match information.
- **Results**: source scan, host, IP, port, protocol, state, service, detection method/confidence, product/version, and NSE script output.

## Limitations

- This tool converts Nmap results; it does not independently validate vulnerabilities.
- Open ports and detected services are not automatically classified as vulnerabilities.
- A combined XML file is a convenience artifact, not a replacement for retaining the original scan files.
- Only XML files are processed in `--combine-dir` mode.
