#!/usr/bin/env python3
"""Run subdomain discovery, DNS checks, HTTP probing and URL crawling.

Requires Python 3.9+. Network stages run on Linux/Kali/WSL;
offline --reprocess-katana also runs on Windows. See README.md.
"""

import argparse
from contextlib import nullcontext
import csv
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit
from uuid import uuid4


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Enter a positive integer.")
    if number <= 0:
        raise argparse.ArgumentTypeError("The value must be greater than zero.")
    return number


def domain_name(value):
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise argparse.ArgumentTypeError("Invalid domain.")

    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(domain) > 253 or not re.fullmatch(
        label + r"(?:\." + label + r")+", domain
    ):
        raise argparse.ArgumentTypeError(
            "Enter a domain, e.g. example.com, without https:// or a path."
        )
    return domain


def arguments():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", required=True, type=domain_name)
    parser.add_argument("-o", type=Path, help="Output directory; reuse with --skip-N")
    parser.add_argument(
        "--reprocess-katana", action="store_true",
        help="Rebuild URL lists from saved Katana output in -o; make no network requests",
    )
    parser.add_argument(
        "--keep-katana-artifacts", action="store_true",
        help="Keep heuristic JS/Markdown artifacts in the main URL list too; raw data is always retained",
    )
    for step, description in enumerate((
        "SubDomz", "DNS bruteforce", "merge and DNS validation",
        "httpx", "Katana", "URL splitting",
    ), 1):
        parser.add_argument(
            f"--skip-{step}", dest="skip_steps", action="append_const", const=step,
            help=f"Skip step {step} ({description}); reuse saved results if needed",
        )
    parser.add_argument(
        "--exclude-host", action="append", type=domain_name, default=[],
        metavar="HOST", help="Exclude a host and its descendants; repeatable",
    )
    parser.add_argument(
        "--exclude-file", type=Path,
        help="File of excluded hostnames, one per line; # comments allowed",
    )
    parser.add_argument(
        "--subdomains-only", action="store_true",
        help="Allow subdomains of -d, but not the root domain itself",
    )
    parser.add_argument(
        "-s",
        type=Path,
        default=Path.home() / "SubDomz",
        help="SubDomz directory or script path",
    )
    parser.add_argument(
        "-r", type=positive_int, help="HTTP requests/s limit for httpx and katana"
    )
    parser.add_argument(
        "--wordlist", type=Path, help="Subdomain wordlist for puredns"
    )
    parser.add_argument(
        "--resolvers",
        type=Path,
        default=Path.home() / ".config/puredns/resolvers.txt",
        help="Public DNS resolver file",
    )
    parser.add_argument(
        "--resolvers-trusted",
        type=Path,
        help="Optional trusted DNS resolver file",
    )
    parser.add_argument(
        "--dns-rate",
        type=positive_int,
        default=100,
        help="Queries/s limit for public resolvers (default: 100)",
    )
    parser.add_argument(
        "--dns-rate-trusted",
        type=positive_int,
        default=50,
        help="Queries/s limit for trusted resolvers (default: 50)",
    )
    parser.add_argument(
        "-P",
        "--skip-puredns",
        action="store_true",
        help="Skip DNS bruteforce and validation; this is NOT passive mode",
    )

    args = parser.parse_args()
    args.skip_steps = set(args.skip_steps or ())
    if args.reprocess_katana:
        if 6 in args.skip_steps:
            parser.error("--reprocess-katana rebuilds URL splits; do not combine it with --skip-6.")
        if args.o is None:
            parser.error("Use -o DIRECTORY with --reprocess-katana.")
        args.skip_steps.update(range(1, 6))
    if args.skip_steps and args.o is None:
        parser.error("Use -o DIRECTORY with --skip-N to select the saved results.")
    if not args.skip_puredns and 2 not in args.skip_steps and args.wordlist is None:
        parser.error("Provide --wordlist, --skip-2, or --skip-puredns.")
    if args.exclude_file is not None:
        try:
            for number, line in enumerate(
                args.exclude_file.expanduser().read_text(encoding="utf-8").splitlines(), 1
            ):
                value = line.split("#", 1)[0].strip()
                if value:
                    try:
                        args.exclude_host.append(domain_name(value))
                    except argparse.ArgumentTypeError as error:
                        parser.error(f"Exclusion file line {number}: {error}")
        except (OSError, UnicodeError) as error:
            parser.error(f"Cannot read exclusion file: {error}")
    args.exclude_host = sorted(set(args.exclude_host))
    if any(args.d == host or args.d.endswith("." + host) for host in args.exclude_host):
        parser.error("The exclusions cover the entire target domain.")
    return args


class HttpScope:

    def __init__(self, domain, excluded=(), subdomains_only=False):
        self.domain = domain
        self.excluded = tuple(excluded)
        self.subdomains_only = subdomains_only

    def allows_host(self, value):
        try:
            host = domain_name(value)
        except argparse.ArgumentTypeError:
            return False
        inside = host.endswith("." + self.domain) or (
            host == self.domain and not self.subdomains_only
        )
        return inside and not any(
            host == denied or host.endswith("." + denied) for denied in self.excluded
        )

    def allows_url(self, value):
        try:
            if (
                not isinstance(value, str) or not value.isascii()
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value)
                or "\\" in value
            ):
                return False
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or parsed.username is not None:
                return False
            if parsed.password is not None or parsed.hostname is None:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            return self.allows_host(parsed.hostname)
        except (ValueError, UnicodeError):
            return False

    @staticmethod
    def url_pattern(host, include_root=True):
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        prefix = "(?:" + label + r"\.)" + ("*" if include_root else "+")
        return r"(?i:^https?://" + prefix + re.escape(host) + r"\.?(?::[0-9]+)?(?:[/?#]|$))"

    def katana_flags(self, output):
        # Regex files prevent goflags from splitting {0,61} at the comma.
        inside = output / "04_katana_scope.txt"
        write_lines(inside, [self.url_pattern(self.domain, not self.subdomains_only)])
        flags = [
            "-cs", inside,
            "-dr",
        ]
        if self.excluded:
            outside = output / "04_katana_excluded_scope.txt"
            write_lines(outside, [self.url_pattern(host) for host in self.excluded])
            flags += ["-cos", outside]
        return flags


def filter_scope_file(path, scope, url=False, rejected_path=None):
    allowed, rejected = [], []
    for value in lines(path):
        if url:
            accepted = scope.allows_url(value)
            normalized = value
        else:
            accepted = scope.allows_host(value)
            normalized = domain_name(value) if accepted else value
        (allowed if accepted else rejected).append(normalized)
    write_lines(path, dict.fromkeys(allowed))
    if rejected_path is not None:
        write_lines(rejected_path, dict.fromkeys(redact_secrets(v) for v in rejected))
    logging.info("%s: kept %d in-scope entries; rejected %d", path.name, len(allowed), len(rejected))
    return list(dict.fromkeys(allowed))


def check_http_scope_support(bins):
    required_flags = {
        "httpx": (
            "-follow-redirects", "-follow-host-redirects", "-config", "-json",
            "-status-code", "-title", "-content-type", "-location", "-ip",
            "-tech-detect", "-response-time", "-web-server", "-content-length",
        ),
        "katana": (
            "-crawl-scope", "-crawl-out-scope", "-disable-redirects",
            "-config", "-error-log", "-silent", "-jsonl", "-no-color",
            "-omit-raw", "-omit-body",
        ),
    }
    for name, flags in required_flags.items():
        if name not in bins:
            continue
        result = subprocess.run(
            [bins[name], "-h"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=15,
            start_new_session=True,
        )
        if result.returncode != 0 or any(flag not in result.stdout for flag in flags):
            raise RuntimeError(
                f"{name} does not advertise the required scope/diagnostic options. "
                "Install a compatible ProjectDiscovery version; no scan was started."
            )


def check_file(path, label):
    path = path.expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"{label}: file not found {path}")
    with path.open("rb") as source:
        if not source.read(1):
            raise RuntimeError(f"{label}: file is empty: {path}")
    return path


def find_subdomz(location):
    location = location.expanduser().resolve()
    if location.is_file():
        return location
    for name in ("SubDomz.sh", "subdomz.sh"):
        candidate = location / name
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"SubDomz script not found in: {location}")


def install_interrupt_confirmation():
    last_press = None

    def confirm_interrupt(signum, frame):
        nonlocal last_press
        now = time.monotonic()
        if last_press is not None and now - last_press <= 3.0:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            raise KeyboardInterrupt
        last_press = now
        # Avoid re-entering the logging machinery from a signal handler.
        os.write(
            2,
            b"\nPress Ctrl+C again within 3 seconds to stop. Pipeline is still running.\n",
        )

    signal.signal(signal.SIGINT, confirm_interrupt)


def stop_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The leader may exit while a descendant is still running in the group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


KATANA_STARTUP_FAILURES = (
    r"could not create runner",
    r"could not compile regex",
    r"could not create scope manager",
    r"could not create crawler options",
)


class ToolStartupError(RuntimeError):
    def __init__(self, message, process_code):
        super().__init__(message)
        self.process_code = process_code


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


SECRET_NAMES = (
    r"key|api[_-]?key|shodan[_-]?api[_-]?key|token|(?:access|refresh|id)[_-]?token"
    r"|client[_-]?secret|secret|password|signature|sig|authorization"
)


def redact_secrets(value):
    """Redact common credentials in diagnostics, not in machine-readable data."""
    value = re.sub(
        r"(?i)([?&](?:" + SECRET_NAMES + r")=)[^&\s\"'<>\\]+",
        r"\1[REDACTED]", value,
    )
    value = re.sub(
        r'(?i)("(?:' + SECRET_NAMES + r')"\s*:\s*)"(?:\\.|[^"\\])*"',
        r'\1"[REDACTED]"', value,
    )
    value = re.sub(
        r"(?i)(\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)[^\s\"'<>,}\\]+",
        r"\1[REDACTED]", value,
    )
    return re.sub(
        r"""(?ix)(--?(?:api[_-]?key|shodan[_-]?api[_-]?key|token|client[_-]?secret|password)
        (?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)""",
        r"\1[REDACTED]", value,
    )


def redact_diagnostic_file(path):
    if path.is_file():
        write_lines(path, (redact_secrets(value) for value in iter_lines(path)))


def run(command, cwd=None, check=True, fatal_patterns=(), log_path=None,
        line_handler=None, result_handler=None):
    command = [str(arg) for arg in command]
    logging.info("Command: %s", redact_secrets(shlex.join(command)))
    started = time.monotonic()
    startup_failure = None
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in fatal_patterns]
    diagnostic = Path(log_path).open("w", encoding="utf-8") if log_path is not None else nullcontext(None)
    with diagnostic as process_log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        try:
            for line in process.stdout:
                clean = ANSI_ESCAPE.sub("", line).strip().lstrip("\ufeff")
                if line_handler is not None:
                    line_handler(clean)
                # Machine data goes to its own file, never to the diagnostic log.
                if result_handler is not None and result_handler(clean):
                    continue
                safe_line = redact_secrets(line)
                logging.info("%s", safe_line.rstrip("\r\n"))
                if process_log is not None:
                    process_log.write(safe_line)
                if startup_failure is None and any(pattern.search(clean) for pattern in compiled):
                    startup_failure = redact_secrets(clean)
            code = process.wait()
        except BaseException:
            stop_process_group(process)
            raise
        finally:
            process.stdout.close()

    logging.info(
        "%s finished in %.2fs with exit code %d",
        Path(command[0]).name, time.monotonic() - started, code,
    )
    if startup_failure is not None:
        raise ToolStartupError(
            f"{Path(command[0]).name}: startup failed (process exit code {code}): {startup_failure}",
            process_code=code,
        )
    if check and code != 0:
        raise RuntimeError(
            f"{command[0]} exited with code {code}; check run.log"
        )
    return code


def iter_lines(path):
    with path.open(encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            value = line.strip()
            if value:
                yield value


def lines(path):
    return list(iter_lines(path))


def write_lines(path, values):
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as output:
            for value in values:
                output.write(value + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def note_issue(issues, output, message):
    if message not in issues:
        issues.append(message)
    write_lines(output / "warnings.txt", issues)
    logging.warning("%s", message)


def dns_options(args, bins):
    options = [
        "--bin", bins["massdns"],
        "--resolvers", args.resolvers,
        "--rate-limit", str(args.dns_rate),
        "--rate-limit-trusted", str(args.dns_rate_trusted),
    ]
    if args.resolvers_trusted:
        options += ["--resolvers-trusted", args.resolvers_trusted]
    return options


def signature(path):
    if not path.is_file():
        return None
    stat = path.stat()
    return stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def category(url):
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return "other"

    if path.endswith((".js", ".mjs", ".cjs")):
        return "js"
    if (
        not path
        or path.endswith("/")
        or path.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp"))
        or "." not in path.rsplit("/", 1)[-1]
    ):
        return "pages"
    return "other"


def scoped_values(path, scope, url=False, required=False):
    if not path.is_file():
        if required:
            raise RuntimeError(f"Missing saved results: {path}")
        return []
    allowed = scope.allows_url if url else scope.allows_host
    return list(dict.fromkeys(
        value if url else domain_name(value)
        for value in lines(path) if allowed(value)
    ))


def write_csv(path, fields, rows):
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for row in rows:
                # Titles and other server-controlled strings must stay text in Excel.
                safe = {}
                for key in fields:
                    value = row.get(key, "")
                    if isinstance(value, str):
                        value = redact_secrets(value)
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                        value = "'" + value
                    safe[key] = value
                writer.writerow(safe)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def saved_scope(output, domain):
    config = output / "scan_config.json"
    if config.is_file():
        try:
            previous = json.loads(config.read_text(encoding="utf-8"))
            if (
                not isinstance(previous, dict)
                or not isinstance(previous.get("domain"), str)
                or not isinstance(previous.get("excluded"), list)
                or not all(isinstance(host, str) for host in previous["excluded"])
                or not isinstance(previous.get("subdomains_only"), bool)
            ):
                raise ValueError("invalid scope fields")
            previous["domain"] = domain_name(previous["domain"])
            previous["excluded"] = [domain_name(host) for host in previous["excluded"]]
        except (ValueError, argparse.ArgumentTypeError) as error:
            raise RuntimeError(f"Cannot read saved scan scope: {config}: {error}")
    else:
        log = output / "run.log"
        previous = None
        if log.is_file():
            for line in iter_lines(log):
                match = re.search(r" INFO: Domain: ([a-z0-9.-]+)\s*$", line)
                if match:
                    previous = {
                        "domain": domain_name(match.group(1)),
                        "excluded": [], "subdomains_only": False,
                    }
                elif previous is not None and " INFO: HTTP scope: " in line:
                    previous["subdomains_only"] = " INFO: HTTP scope: *." in line
                elif previous is not None and " INFO: Excluded HTTP hosts and descendants: " in line:
                    denied = line.split(" INFO: Excluded HTTP hosts and descendants: ", 1)[1].strip()
                    previous["excluded"] = [] if denied == "none" else [
                        domain_name(v.strip()) for v in denied.split(",")
                    ]
        if previous is None:
            raise RuntimeError(
                f"Cannot identify the target in {output}; "
                "saved scan_config.json or an original run.log is required."
            )
    if previous["domain"] != domain:
        raise RuntimeError(
            f"Saved results target {previous['domain']}, but -d specifies {domain}."
        )
    return previous


def run_subdomz(args, bins, target, output, issues):
    script = find_subdomz(args.s)
    requested = script.parent / f"subdomz_requested_{uuid4().hex}.txt"
    fallback = script.parent / f"subdomz-{args.d}.txt"
    old_fallback = signature(fallback)
    write_lines(target, [])
    found, rejected = {}, {}

    def collect(value, keep_rejected=False):
        value = ANSI_ESCAPE.sub("", value).strip()
        if not value:
            return
        try:
            host = domain_name(value)
        except argparse.ArgumentTypeError:
            if keep_rejected:
                rejected[redact_secrets(value)] = None
            return
        if host == args.d or host.endswith("." + args.d):
            found[host] = None
        elif keep_rejected:
            rejected[host] = None

    try:
        code = run([
            bins["bash"], script, "-d", args.d,
            "-e", "Puredns", "-o", requested,
        ], cwd=script.parent, check=False, line_handler=collect)
        if code:
            note_issue(issues, output, f"SubDomz: exit code {code}; keeping partial results")
    except KeyboardInterrupt:
        note_issue(issues, output, "SubDomz: interrupted; preserving available partial results")
        raise
    finally:
        # Recover partial data before cleanup, including after an interruption.
        candidates = [requested]
        if signature(fallback) != old_fallback:
            candidates.append(fallback)
        for source in candidates:
            if source.is_file():
                for value in lines(source):
                    collect(value, keep_rejected=True)
        write_lines(target, found)
        write_lines(output / "01_subdomz_rejected.txt", rejected)
        if rejected:
            note_issue(issues, output, f"SubDomz: discarded {len(rejected)} invalid or unrelated output lines")
        if not found:
            note_issue(
                issues, output,
                "SubDomz: no valid fresh hostnames; check network/VPN, API keys and tool dependencies in run.log",
            )
        logging.info("SubDomz results: %d valid target hostnames", len(found))
        requested.unlink(missing_ok=True)


def parse_http_results(path, scope, output, issues):
    rows, urls, rejected = [], [], []
    malformed = failed = 0
    for number, line in enumerate(iter_lines(path), 1):
        try:
            record = json.loads(line)
            if not isinstance(record, dict) or not isinstance(record.get("url"), str):
                raise ValueError("expected an object with a URL")
            url = record["url"]
            if not scope.allows_url(url):
                rejected.append(url)
                continue
            status = record.get("status_code")
            error = record.get("error", "")
            valid_status = isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599
            if record.get("failed") or not valid_status:
                failed += 1
            else:
                urls.append(url)
            tech = record.get("tech") or []
            rows.append({
                "url": url, "status_code": status if valid_status else "",
                "title": record.get("title", ""),
                "content_type": record.get("content_type", ""),
                "location": record.get("location", ""),
                "ip": record.get("host_ip") or record.get("host", ""),
                "technologies": "; ".join(str(item) for item in tech) if isinstance(tech, list) else str(tech),
                "response_time": record.get("time", record.get("response_time", "")),
                "server": record.get("webserver", ""),
                "content_length": record.get("content_length", ""),
                "input": record.get("input", ""), "error": error,
            })
        except (ValueError, TypeError):
            malformed += 1
            logging.warning("httpx: invalid JSON record at nonempty line %d", number)
    write_lines(output / "03_rejected_urls.txt", dict.fromkeys(redact_secrets(v) for v in rejected))
    write_csv(output / "03_httpx_details.csv", (
        "url", "status_code", "title", "content_type", "location", "ip",
        "technologies", "response_time", "server", "content_length", "input", "error",
    ), rows)
    if malformed:
        note_issue(issues, output, f"httpx: {malformed} malformed JSON records; raw output preserved")
    if failed:
        note_issue(issues, output, f"httpx: {failed} records without a successful HTTP exchange; see JSONL/CSV")
    return list(dict.fromkeys(urls))


def jsonl_collector(target):
    """Return a stdout handler that saves JSON records without logging copies."""
    def collect(value):
        if value.startswith("{"):
            target.write(value + "\n")
            return True
        return False
    return collect


def probe_http(args, bins, domains, scope, output, config, issues):
    raw = output / "03_httpx_results.jsonl"
    live = output / "03_httpx_live.txt"
    source = output / "03_httpx_input.txt"
    write_lines(source, domains)
    for path in (raw, live, output / "03_rejected_urls.txt"):
        write_lines(path, [])
    parse_http_results(raw, scope, output, issues)
    if not domains:
        raise RuntimeError("No in-scope hostnames available for httpx.")
    interrupted = False
    try:
        with raw.open("w", encoding="utf-8", newline="\n") as target:
            code = run([
                bins["httpx"], "-l", source, "-json",
                "-status-code", "-title", "-content-type", "-location", "-ip",
                "-tech-detect", "-response-time", "-web-server", "-content-length",
                "-config", config, "-follow-redirects=false", "-follow-host-redirects=false",
            ] + (["-rl", str(args.r)] if args.r is not None else []),
                check=False, result_handler=jsonl_collector(target))
    except KeyboardInterrupt:
        code = 130
        interrupted = True
    hosts = parse_http_results(raw, scope, output, issues)
    write_lines(live, hosts)
    if code:
        note_issue(issues, output, f"httpx: exit code {code}; partial results retained")
    logging.info("httpx: %d in-scope live URLs; details in 03_httpx_details.csv", len(hosts))
    if interrupted:
        raise KeyboardInterrupt
    return hosts


KATANA_VERBOSE_URL = re.compile(
    r"^(?:\[[A-Za-z0-9_:-]+\]\s*)*"
    r"\[(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\]\s+"
    r"(https?://\S+?)(?:\s+\[depth:\d+\])?$", re.IGNORECASE,
)
KATANA_RECORD_PREFIX = re.compile(
    r"^(?:\[[^\]\r\n]+\]\s*)*"
    r"\[(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\]\s+https?://",
    re.IGNORECASE,
)
PIPELINE_LOG_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+\s+(?:INFO|WARNING|ERROR):\s+"
)


def katana_endpoint(line):
    """Extract only result records; never fish URLs out of diagnostic messages."""
    value = ANSI_ESCAPE.sub("", line).strip().lstrip("\ufeff")
    value = PIPELINE_LOG_PREFIX.sub("", value)
    if value.startswith("{"):
        try:
            record = json.loads(value)
        except ValueError:
            return None
        request = record.get("request") if isinstance(record, dict) else None
        endpoint = request.get("endpoint") if isinstance(request, dict) else None
        return endpoint if isinstance(endpoint, str) else None
    # Our review inventory is also a lossless source for repeated legacy recovery.
    marked = re.fullmatch(
        r"(?:javascript-escape|javascript-template|encoded-control-character)\t(https?://\S+)",
        value,
    )
    if marked:
        return marked.group(1)
    match = KATANA_VERBOSE_URL.fullmatch(value)
    if match:
        return match.group(1)
    if value.lower().startswith(("http://", "https://")):
        return value
    return None


def katana_artifact_reason(url):
    """Conservative review heuristic, distinct from scope validation."""
    path = unquote(urlsplit(url).path)
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return "encoded-control-character"
    if re.search(r"\\(?:[nrt]|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})", path):
        return "javascript-escape"
    if "$" + "{" in path:
        return "javascript-template"
    return None


def parse_katana_results(paths, scope, output, issues,
                         rejected_name="04_rejected_urls.txt", keep_artifacts=False):
    accepted, rejected, suspicious = {}, {}, {}
    malformed_values = {}
    seen = set()
    malformed = ignored = extracted = 0
    paths = list(dict.fromkeys(paths))
    for path in paths:
        with path.open(encoding="utf-8-sig", errors="replace") as source:
            for line in source:
                if not line.strip():
                    continue
                url = katana_endpoint(line)
                if url is None:
                    value = PIPELINE_LOG_PREFIX.sub(
                        "", ANSI_ESCAPE.sub("", line).strip().lstrip("\ufeff"),
                    )
                    if path.suffix == ".jsonl" or value.startswith("{") or KATANA_RECORD_PREFIX.match(value):
                        malformed += 1
                        safe = redact_secrets(value).replace("\r", r"\r").replace("\n", r"\n")
                        if len(safe) > 4096:
                            safe = safe[:4096] + " ... [truncated; inspect original source]"
                        malformed_values[safe] = None
                    else:
                        ignored += 1
                    continue
                extracted += 1
                if url in seen:
                    continue
                seen.add(url)
                if not scope.allows_url(url):
                    rejected[redact_secrets(url).replace("\r", r"\r").replace("\n", r"\n")] = None
                    continue
                url = urlsplit(url)._replace(fragment="").geturl()
                reason = katana_artifact_reason(url)
                if reason:
                    suspicious[url] = reason
                    if not keep_artifacts:
                        continue
                accepted[url] = None
    write_lines(output / "04_katana_urls.txt", accepted)
    write_lines(output / rejected_name, rejected)
    write_lines(output / "04_malformed_records.log", malformed_values)
    write_lines(
        output / "04_suspicious_urls.txt",
        (reason + "\t" + url for url, reason in suspicious.items()),
    )
    summary = {
        "sources": [str(path) for path in paths],
        "extracted_records": extracted, "unique_extracted_urls": len(seen),
        "accepted_unique_urls": len(accepted),
        "rejected_unique_urls": len(rejected), "suspicious_unique_urls": len(suspicious),
        "malformed_records": malformed, "diagnostic_lines": ignored,
        "keep_artifacts": keep_artifacts,
        "note": "Heuristics can flag legitimate URLs. Raw sources are retained. Emitted URLs do not prove HTTP success.",
    }
    write_lines(output / "04_katana_parse_summary.json", [json.dumps(summary, indent=2)])
    logging.info(
        "Katana output: %d in-scope URLs, %d rejected, %d suspicious, %d malformed, %d diagnostic lines",
        len(accepted), len(rejected), len(suspicious), malformed, ignored,
    )
    if malformed:
        note_issue(issues, output, f"Katana: {malformed} malformed output records; source files retained")
    if suspicious:
        logging.info("Heuristic artifacts are listed in 04_suspicious_urls.txt; raw sources were retained.")
    return list(accepted)


def katana_sources(output):
    """Prefer usable machine output; otherwise merge available legacy sources."""
    raw = output / "04_katana_results.jsonl"
    nonempty_raw = raw.is_file() and raw.stat().st_size > 0
    if nonempty_raw and any(katana_endpoint(line) is not None for line in iter_lines(raw)):
        return [raw]
    sources = [raw] if nonempty_raw else []
    for name in (
        "04_katana_urls.txt", "04_rejected_urls.txt",
        "04_katana_process.log", "04_suspicious_urls.txt",
    ):
        path = output / name
        if path.is_file() and path.stat().st_size:
            sources.append(path)
    process_log = output / "04_katana_process.log"
    if not (process_log.is_file() and process_log.stat().st_size):
        # Keep the original fallback on later reprocessing passes as well.
        # The generated aggregate alone omits artifacts excluded on the first pass.
        log = output / "run.log"
        if log.is_file() and log.stat().st_size:
            sources.append(log)
    return list(dict.fromkeys(sources))


def crawl_hosts(args, bins, hosts, scope, output, config, issues):
    source = output / "04_katana_input.txt"
    aggregate = output / "04_katana_urls.txt"
    raw = output / "04_katana_results.jsonl"
    errors = output / "04_katana_errors.log"
    process_log = output / "04_katana_process.log"
    rejected_file = output / "04_rejected_urls.txt"
    hosts = list(dict.fromkeys(url for url in hosts if scope.allows_url(url)))
    write_lines(source, hosts)
    for target in (aggregate, raw, errors, rejected_file, process_log):
        write_lines(target, [])
    if not hosts:
        parse_katana_results(
            [raw], scope, output, issues,
            keep_artifacts=getattr(args, "keep_katana_artifacts", False),
        )
        note_issue(issues, output, "Katana: no live input URLs; no hosts crawled")
        return []
    if (output / "04_katana_summary.csv").exists() or (output / "04_katana_hosts").exists():
        logging.info("Per-host artifacts from earlier runs are historical and are not updated.")
    scope_flags = scope.katana_flags(output)
    logging.info("Katana: one process for all %d input URLs", len(hosts))
    started = time.monotonic()
    interrupted = False
    startup_error = None
    try:
        with raw.open("w", encoding="utf-8", newline="\n") as target:
            code = run([
                bins["katana"], "-list", source, "-silent", "-elog", errors,
                "-jsonl", "-nc", "-or", "-ob",
                "-jc", "-kf", "all", "-config", config,
            ] + scope_flags + (["-rl", str(args.r)] if args.r is not None else []),
                check=False, fatal_patterns=KATANA_STARTUP_FAILURES,
                log_path=process_log, result_handler=jsonl_collector(target))
    except ToolStartupError as error:
        code = error.process_code
        startup_error = error
    except KeyboardInterrupt:
        code = 130
        interrupted = True
    elapsed = time.monotonic() - started
    accepted = parse_katana_results(
        [raw, process_log], scope, output, issues,
        keep_artifacts=getattr(args, "keep_katana_artifacts", False),
    )
    redact_diagnostic_file(errors)
    request_errors = lines(errors) if errors.is_file() else []
    if not errors.exists():
        write_lines(errors, [])
    logging.info("Katana stage: %d URLs, %d request errors, %.2fs total, process exit %d",
                 len(accepted), len(request_errors), elapsed, code)
    if startup_error is not None:
        with errors.open("a", encoding="utf-8") as target:
            target.write(f"[startup failure] {startup_error}\n")
        note_issue(issues, output, f"Katana: startup failed (process exit {code}); see 04_katana_process.log")
        raise startup_error
    if code:
        note_issue(issues, output, f"Katana: exit code {code}; partial results retained")
    if not accepted:
        note_issue(issues, output, "Katana: zero in-scope output URLs; inspect 04_katana_process.log")
    if request_errors:
        note_issue(issues, output, f"Katana: {len(request_errors)} request errors; coverage may be incomplete")
    if interrupted:
        raise KeyboardInterrupt
    return accepted


def split_results(urls, output):
    groups = {"js": [], "pages": [], "other": []}
    for url in urls:
        groups[category(url)].append(url)
    for name, values in groups.items():
        write_lines(output / f"05_split_{name}.txt", values)
        logging.info("%s: %d unique URLs", name, len(values))


def configure_logging(output):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(output / "run.log", encoding="utf-8")],
        force=True,
    )


def reprocess_katana(output, scope, keep_artifacts=False):
    sources = katana_sources(output)
    if not sources:
        raise RuntimeError("No saved Katana output found to reprocess.")
    issues = lines(output / "warnings.txt") if (output / "warnings.txt").is_file() else []
    issues = [message for message in issues if not (
        message.startswith("Katana: zero in-scope output URLs")
        or re.match(r"Katana: \d+ malformed output records;", message)
    )]
    logging.info("Reprocessing saved Katana output; no network requests will be made.")
    urls = parse_katana_results(
        sources, scope, output, issues, rejected_name="04_reprocess_rejected_urls.txt",
        keep_artifacts=keep_artifacts,
    )
    if not urls:
        note_issue(issues, output, "Katana: zero in-scope output URLs after reprocessing")
    split_results(urls, output)
    write_lines(output / "warnings.txt", issues)
    logging.info("Reprocessed %d unique in-scope URLs. Results: %s", len(urls), output)
    return 2 if issues else 0


def main():
    args = arguments()
    skipped = set(args.skip_steps)
    output = (args.o or Path(f"recon-{args.d}-{datetime.now():%Y%m%d-%H%M%S-%f}")).expanduser().resolve()
    if args.reprocess_katana:
        if not output.is_dir():
            raise RuntimeError(f"Saved output directory not found: {output}")
        previous = saved_scope(output, args.d)
        scope = HttpScope(
            args.d, sorted(set(args.exclude_host) | set(previous["excluded"])),
            args.subdomains_only or previous["subdomains_only"],
        )
        configure_logging(output)
        return reprocess_katana(
            output, scope, keep_artifacts=getattr(args, "keep_katana_artifacts", False),
        )
    if os.name != "posix":
        raise RuntimeError("Run network stages on Linux/Kali/WSL; offline --reprocess-katana works on Windows.")
    resuming = output.is_dir() and any(output.iterdir())
    if output.exists() and not output.is_dir():
        raise RuntimeError(f"Output path is not a directory: {output}")
    if resuming and not skipped:
        raise RuntimeError(f"Use a new directory or --skip-N to reuse saved results: {output}")
    if resuming:
        previous = saved_scope(output, args.d)
        args.exclude_host = sorted(set(args.exclude_host) | set(previous["excluded"]))
        args.subdomains_only = args.subdomains_only or previous["subdomains_only"]
    scope = HttpScope(args.d, args.exclude_host, args.subdomains_only)
    if not scope.allows_host("scope-check." + args.d):
        if any(args.d == host or args.d.endswith("." + host) for host in args.exclude_host):
            raise RuntimeError("The saved exclusions cover the target domain.")

    subdomz_raw = output / "01_subdomz_raw.txt"
    brute = output / "01_puredns.txt"
    deduped = output / "02_subdomains_deduped.txt"
    resolved = output / "02_dns_resolved.txt"
    live = output / "03_httpx_live.txt"
    crawled = output / "04_katana_urls.txt"
    needed = []
    if 3 in skipped and 4 not in skipped:
        needed.append(deduped if args.skip_puredns else resolved)
    if 4 in skipped and 5 not in skipped:
        needed.append(live)
    if 5 in skipped and 6 not in skipped:
        needed.append(crawled)
    for path in needed:
        if not path.is_file():
            raise RuntimeError(f"Missing saved input required by an active step: {path}")

    required = []
    if 1 not in skipped:
        find_subdomz(args.s)
        required.append("bash")
    dns_active = not args.skip_puredns and (2 not in skipped or 3 not in skipped)
    if dns_active:
        required += ["puredns", "massdns"]
        args.resolvers = check_file(args.resolvers, "Resolvers")
        if args.resolvers_trusted:
            args.resolvers_trusted = check_file(args.resolvers_trusted, "Trusted resolvers")
    if not args.skip_puredns and 2 not in skipped:
        args.wordlist = check_file(args.wordlist, "Wordlist")
    if 4 not in skipped:
        required.append("httpx")
    if 5 not in skipped:
        required.append("katana")
    bins = {}
    for name in required:
        bins[name] = shutil.which(name)
        if not bins[name]:
            raise RuntimeError(f"Could not find {name} in PATH.")
    check_http_scope_support(bins)

    old_issues = lines(output / "warnings.txt") if resuming and (output / "warnings.txt").is_file() else []
    issue_steps = {"SubDomz:": 1, "Puredns bruteforce:": 2, "Puredns resolve:": 3, "httpx:": 4, "Katana:": 5}
    issues = []
    for message in old_issues:
        stage = next((stage for prefix, stage in issue_steps.items() if message.startswith(prefix)), None)
        if stage in skipped or (stage is None and skipped):
            issues.append(message)
    output.mkdir(parents=True, exist_ok=True)
    configure_logging(output)
    write_lines(output / "warnings.txt", issues)
    logging.info("=== New pipeline run; skipped steps: %s ===", ", ".join(map(str, sorted(skipped))) or "none")
    logging.info("Domain: %s", args.d)
    logging.info("Results: %s", output)
    logging.info("HTTP scope: %s%s", "*." if args.subdomains_only else "root and subdomains of ", args.d)
    logging.info("Excluded HTTP hosts and descendants: %s", ", ".join(args.exclude_host) or "none")
    logging.info("HTTP redirects are disabled in httpx and Katana.")
    logging.warning("HTTP scope guards do not control DNS queries or tools launched inside SubDomz.")
    (output / "scan_config.json").write_text(json.dumps({
        "domain": args.d, "excluded": args.exclude_host, "subdomains_only": args.subdomains_only,
    }, indent=2) + "\n", encoding="utf-8")
    config = output / "http-tools-config.yaml"
    config.write_text("{}\n", encoding="utf-8")

    logging.info("Step 1/6: SubDomz%s", " [SKIPPED]" if 1 in skipped else "")
    if 1 not in skipped:
        run_subdomz(args, bins, subdomz_raw, output, issues)

    logging.info("Step 2/6: DNS bruteforce%s", " [SKIPPED]" if 2 in skipped or args.skip_puredns else "")
    if 2 not in skipped and not args.skip_puredns:
        write_lines(brute, [])
        code = run([
            bins["puredns"], "bruteforce", args.wordlist, args.d,
            "--write", brute,
        ] + dns_options(args, bins), check=False)
        if code:
            note_issue(issues, output, f"Puredns bruteforce: exit code {code}; keeping partial results")
    elif not resuming and not brute.exists():
        write_lines(brute, [])

    domains = []
    logging.info("Step 3/6: merge and DNS validation%s", " [SKIPPED]" if 3 in skipped else "")
    if 3 not in skipped:
        write_lines(deduped, dict.fromkeys(
            (lines(subdomz_raw) if subdomz_raw.is_file() else [])
            + (lines(brute) if brute.is_file() else [])
        ))
        domains = filter_scope_file(deduped, scope, rejected_path=output / "02_rejected_domains.txt")
        write_lines(resolved, [])
        write_lines(output / "02_rejected_dns.txt", [])
        write_lines(output / "02_unrequested_dns.txt", [])
        if not domains:
            raise RuntimeError("No in-scope candidates after merging; check steps 1/2 or saved inputs.")
        if not args.skip_puredns:
            code = run([
                bins["puredns"], "resolve", deduped, "--write", resolved,
            ] + dns_options(args, bins), check=False)
            if code:
                note_issue(issues, output, f"Puredns resolve: exit code {code}; keeping partial results")
            validated = filter_scope_file(resolved, scope, rejected_path=output / "02_rejected_dns.txt") if resolved.is_file() else []
            candidate_set = set(domains)
            unexpected = [host for host in validated if host not in candidate_set]
            if unexpected:
                note_issue(issues, output, f"Puredns resolve: discarded {len(unexpected)} unrequested hostnames")
                write_lines(output / "02_unrequested_dns.txt", unexpected)
            unexpected_set = set(unexpected)
            domains = [host for host in validated if host not in unexpected_set]
            write_lines(resolved, domains)
            if not domains:
                note_issue(issues, output, "Puredns resolve: no validated candidates; no new HTTP probing")
                raise RuntimeError("No DNS-validated candidates; original candidates were preserved.")
        else:
            logging.info("DNS validation skipped with --skip-puredns; HTTP input is unvalidated.")
    elif 4 not in skipped:
        domains = scoped_values(deduped if args.skip_puredns else resolved, scope, required=True)

    logging.info("Step 4/6: httpx%s", " [SKIPPED]" if 4 in skipped else "")
    hosts = []
    if 4 not in skipped:
        hosts = probe_http(args, bins, domains, scope, output, config, issues)
        if not hosts:
            note_issue(issues, output, "httpx: no in-scope live URLs; no new crawl inputs")
    elif 5 not in skipped:
        hosts = scoped_values(live, scope, url=True, required=True)

    logging.info("Step 5/6: Katana%s", " [SKIPPED]" if 5 in skipped else "")
    urls = []
    if 5 not in skipped:
        if 6 not in skipped:
            split_results([], output)
        try:
            urls = crawl_hosts(args, bins, hosts, scope, output, config, issues)
        except (KeyboardInterrupt, ToolStartupError):
            if 6 not in skipped:
                split_results(scoped_values(crawled, scope, url=True), output)
            raise
    elif 6 not in skipped:
        urls = scoped_values(crawled, scope, url=True, required=True)

    logging.info("Step 6/6: URL splitting%s", " [SKIPPED]" if 6 in skipped else "")
    if 6 not in skipped:
        split_results(urls, output)
    logging.info("Results: %s", output)
    if issues:
        logging.warning("Completed with partial or suspect results (exit code 2); see warnings.txt and run.log.")
    else:
        logging.info("Pipeline completed without detected stage errors.")
    return 2 if issues else 0


if __name__ == "__main__":
    install_interrupt_confirmation()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.error("Interrupted by the user.")
        sys.exit(130)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        logging.error("%s", error)
        sys.exit(1)
