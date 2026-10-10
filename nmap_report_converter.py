#!/usr/bin/env python3

import argparse
import glob
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from libnmap.parser import NmapParser, NmapParserException
from xlsxwriter import Workbook


class HostModule:
    def __init__(self, host, scan_name=""):
        self.scan = scan_name
        self.host = next(iter(host.hostnames), "")
        self.ip = getattr(host, "address", "")
        self.port = ""
        self.protocol = ""
        self.status = ""
        self.service = ""
        self.tunnel = ""
        self.method = ""
        self.source = ""
        self.confidence = ""
        self.reason = ""
        self.product = ""
        self.version = ""
        self.extra = ""
        self.flagged = "N/A"
        self.notes = ""


class ServiceModule(HostModule):
    def __init__(self, host, service, scan_name=""):
        super().__init__(host, scan_name)
        self.port = getattr(service, "port", "")
        self.protocol = getattr(service, "protocol", "")
        self.status = getattr(service, "state", "")
        self.service = getattr(service, "service", "")
        self.tunnel = getattr(service, "tunnel", "")
        service_dict = getattr(service, "service_dict", {}) or {}
        self.method = service_dict.get("method", "")
        self.source = "scanner"
        try:
            self.confidence = float(service_dict.get("conf", "0")) / 10
        except (TypeError, ValueError):
            self.confidence = ""
        self.reason = getattr(service, "reason", "")
        self.product = service_dict.get("product", "")
        self.version = service_dict.get("version", "")
        self.extra = service_dict.get("extrainfo", "")


class HostScriptModule(HostModule):
    def __init__(self, host, script, scan_name=""):
        super().__init__(host, scan_name)
        self.method = script.get("id", "")
        self.source = "script"
        self.extra = script.get("output", "").strip()


class ServiceScriptModule(ServiceModule):
    def __init__(self, host, service, script, scan_name=""):
        super().__init__(host, service, scan_name)
        self.source = "script"
        self.method = script.get("id", "")
        self.extra = script.get("output", "").strip()


def safe_attr(obj, name, default=""):
    try:
        value = getattr(obj, name, default)
        return default if value is None else value
    except Exception:
        return default


def write_cell(sheet, row, col, value, cell_format=None):
    if value is None:
        value = ""
    if isinstance(value, str):
        sheet.write_string(row, col, value, cell_format)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        sheet.write_number(row, col, value, cell_format)
    else:
        sheet.write_string(row, col, str(value), cell_format)


def write_header(sheet, headers, header_format):
    for col, header in enumerate(headers):
        write_cell(sheet, 0, col, header, header_format)


def finish_sheet(sheet, headers, widths=None):
    sheet.freeze_panes(1, 0)
    if headers:
        sheet.autofilter(0, 0, max(sheet.dim_rowmax or 0, 0), len(headers) - 1)
    if widths:
        for col, width in enumerate(widths):
            sheet.set_column(col, col, width)


def format_timestamp(value):
    try:
        if not value:
            return "N/A"
        return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError, OverflowError):
        return "N/A"


def generate_summary(workbook, sheet, report, header_format):
    headers = [
        "Scan", "Command", "Version", "Scan Type", "Started", "Completed",
        "Hosts Total", "Hosts Up", "Hosts Down"
    ]
    if sheet.dim_rowmax is None:
        write_header(sheet, headers, header_format)

    row = (sheet.dim_rowmax or 0) + 1
    values = [
        safe_attr(report, "basename", "N/A"),
        safe_attr(report, "commandline", "N/A"),
        safe_attr(report, "version", "N/A"),
        safe_attr(report, "scan_type", "N/A"),
        format_timestamp(safe_attr(report, "started", 0)),
        format_timestamp(safe_attr(report, "endtime", 0)),
        safe_attr(report, "hosts_total", "N/A"),
        safe_attr(report, "hosts_up", "N/A"),
        safe_attr(report, "hosts_down", "N/A"),
    ]
    for col, value in enumerate(values):
        write_cell(sheet, row, col, value)
    finish_sheet(sheet, headers, [28, 55, 14, 16, 24, 24, 14, 12, 13])


def generate_hosts(workbook, sheet, report, scan_name, header_format):
    headers = ["Scan", "Host", "IP", "Status", "Services", "OS"]
    if sheet.dim_rowmax is None:
        write_header(sheet, headers, header_format)

    row = (sheet.dim_rowmax or 0) + 1
    for host in report.hosts:
        os_matches = []
        try:
            for match in host.os_class_probabilities():
                vendor = getattr(match, "vendor", "") or ""
                family = getattr(match, "osfamily", "") or ""
                accuracy = getattr(match, "accuracy", "")
                os_matches.append(f"{vendor} {family} ({accuracy}%)".strip())
        except (AttributeError, TypeError):
            pass

        values = [
            scan_name,
            next(iter(getattr(host, "hostnames", []) or []), ""),
            getattr(host, "address", ""),
            getattr(host, "status", ""),
            len(getattr(host, "services", []) or []),
            " | ".join(os_matches),
        ]
        for col, value in enumerate(values):
            write_cell(sheet, row, col, value)
        row += 1

    finish_sheet(sheet, headers, [28, 30, 18, 14, 12, 48])


def generate_results(workbook, sheet, report, scan_name, header_format):
    headers = [
        "Scan", "Host", "IP", "Port", "Protocol", "Status", "Service", "Tunnel",
        "Source", "Method", "Confidence", "Reason", "Product", "Version",
        "Extra", "Flagged", "Notes"
    ]
    if sheet.dim_rowmax is None:
        write_header(sheet, headers, header_format)

    row = (sheet.dim_rowmax or 0) + 1
    for host in report.hosts:
        modules = []
        for script in getattr(host, "scripts_results", []) or []:
            modules.append(HostScriptModule(host, script, scan_name))

        for service in getattr(host, "services", []) or []:
            modules.append(ServiceModule(host, service, scan_name))
            for script in getattr(service, "scripts_results", []) or []:
                modules.append(ServiceScriptModule(host, service, script, scan_name))

        for module in modules:
            values = [
                module.scan, module.host, module.ip, module.port, module.protocol,
                module.status, module.service, module.tunnel, module.source,
                module.method, module.confidence, module.reason, module.product,
                module.version, module.extra, module.flagged, module.notes
            ]
            for col, value in enumerate(values):
                write_cell(sheet, row, col, value)
            row += 1

    finish_sheet(
        sheet, headers,
        [28, 28, 18, 10, 12, 12, 20, 12, 12, 24, 12, 18, 24, 20, 55, 12, 30]
    )


def load_report(xml_path):
    try:
        ET.parse(xml_path)
    except (ET.ParseError, OSError) as exc:
        raise ValueError(f"Cannot read valid XML from '{xml_path}': {exc}") from exc

    try:
        report = NmapParser.parse_fromfile(xml_path)
    except NmapParserException as first_error:
        try:
            report = NmapParser.parse_fromfile(xml_path, incomplete=True)
        except Exception as second_error:
            raise ValueError(
                f"Could not parse Nmap report '{xml_path}'. "
                f"Normal parse: {first_error}; incomplete parse: {second_error}"
            ) from second_error
    except Exception as exc:
        raise ValueError(f"Could not parse Nmap report '{xml_path}': {exc}") from exc

    report.basename = os.path.basename(xml_path)
    return report


def merge_xml(xml_files, output_xml):
    if not xml_files:
        raise ValueError("No XML files were provided for merging.")

    base_tree = ET.parse(xml_files[0])
    base_root = base_tree.getroot()

    for xml_path in xml_files[1:]:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            base_root.append(host)

    base_tree.write(output_xml, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Nmap XML reports to XLSX and optionally combine XML host observations."
    )
    parser.add_argument("-o", "--output", required=True, help="Output XLSX file")
    parser.add_argument("--combine-dir", help="Directory containing Nmap XML files to process and combine")
    parser.add_argument("reports", nargs="*", help="Nmap XML report files")
    args = parser.parse_args()

    if args.combine_dir:
        if not os.path.isdir(args.combine_dir):
            parser.error(f"Directory does not exist: {args.combine_dir}")
        xml_files = sorted(glob.glob(os.path.join(args.combine_dir, "*.xml")))
        if not xml_files:
            parser.error(f"No XML files found in directory: {args.combine_dir}")
    else:
        if not args.reports:
            parser.error("Provide one or more Nmap XML reports, or use --combine-dir.")
        xml_files = args.reports

    output_xlsx = os.path.abspath(args.output)
    input_paths = {os.path.abspath(path) for path in xml_files}
    if output_xlsx in input_paths:
        parser.error("The XLSX output path must not overwrite an input XML file.")

    output_xml = None
    if args.combine_dir:
        output_xml = os.path.splitext(output_xlsx)[0] + ".xml"
        if os.path.abspath(output_xml) in input_paths:
            parser.error("The combined XML output path would overwrite an input XML file.")

    reports = []
    errors = []
    for xml_path in xml_files:
        try:
            reports.append(load_report(xml_path))
        except ValueError as exc:
            errors.append(str(exc))

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        parser.error("One or more input reports could not be processed; no output was written.")

    try:
        workbook = Workbook(args.output)
        header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "text_wrap": True})
        summary_sheet = workbook.add_worksheet("Summary")
        hosts_sheet = workbook.add_worksheet("Hosts")
        results_sheet = workbook.add_worksheet("Results")

        for report, xml_path in zip(reports, xml_files):
            scan_name = os.path.basename(xml_path)
            generate_summary(workbook, summary_sheet, report, header_format)
            generate_hosts(workbook, hosts_sheet, report, scan_name, header_format)
            generate_results(workbook, results_sheet, report, scan_name, header_format)

        workbook.close()
    except Exception as exc:
        print(f"ERROR: Failed to create Excel report: {exc}", file=sys.stderr)
        raise SystemExit(1)

    if output_xml:
        try:
            merge_xml(xml_files, output_xml)
            print(f"Combined XML written to: {output_xml}")
            print("Note: duplicate host observations are preserved; root-level scan metadata comes from the first input XML.")
        except (ET.ParseError, OSError, ValueError) as exc:
            print(f"ERROR: Failed to create combined XML: {exc}", file=sys.stderr)
            raise SystemExit(1)

    print(f"Excel report written to: {args.output}")
    print(f"Processed {len(reports)} Nmap report(s). Duplicate host observations are preserved.")


if __name__ == "__main__":
    main()
