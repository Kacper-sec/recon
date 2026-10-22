# Recon

A Python script that runs subdomain discovery, DNS bruteforce, DNS validation, HTTP probing and web crawling in sequence. Results are saved in one directory, with crawled URLs split into JavaScript files, pages and other resources.

## Requirements

- Linux, Kali Linux or WSL with Python 3.9+ and Bash.
- [SubDomz](https://github.com/0xPugal/SubDomz) and its dependencies, installed in `~/SubDomz` or a location supplied with `-s`.
- ProjectDiscovery [httpx](https://github.com/projectdiscovery/httpx) and [Katana](https://github.com/projectdiscovery/katana) available in `PATH`.
- [puredns](https://github.com/d3mondev/puredns) and [massdns](https://github.com/blechschmidt/massdns) available in `PATH` for the DNS stages.
- A subdomain wordlist and a DNS resolver file.

Install the external tools using their official instructions. The script uses only the Python standard library; no `pip install` is needed.

SubDomz needs write access to its installation directory. Run only one pipeline instance per SubDomz installation at a time.

## Quick start

Download `recon.py`, then run:

```bash
python3 recon.py -d example.com \
  --wordlist /path/to/subdomains.txt \
  --resolvers /path/to/resolvers.txt \
  -o ./results-example \
  -r 20
```

Replace the domain and file paths with your own. Use a new output directory for a new scan, or omit `-o` to create a directory automatically. Only scan targets you are authorized to test.

For all available options:

```bash
python3 recon.py --help
```

## Pipeline

| Stage | Action | Skip flag |
| --- | --- | --- |
| 1 | Discover subdomains with SubDomz; its built-in puredns step is disabled | `--skip-1` |
| 2 | Run DNS bruteforce with puredns and the supplied wordlist | `--skip-2` |
| 3 | Merge and deduplicate candidates, filter scope and validate DNS | `--skip-3` |
| 4 | Probe HTTP services with httpx and save detailed results | `--skip-4` |
| 5 | Crawl the live URL list with one Katana process | `--skip-5` |
| 6 | Split crawled URLs into JavaScript, pages and other resources | `--skip-6` |

### Reuse saved results

Combine skip flags with `-o` to select an existing results directory. For example, rerun Katana and URL splitting:

```bash
python3 recon.py -d example.com -o ./results-example \
  --skip-1 --skip-2 --skip-3 --skip-4 -r 20
```

Skipped stages keep their existing files. Missing discovery files contribute no candidates; a missing file required by a later active stage stops the run with an error. Skipping a stage does not resume progress inside that stage.

`--skip-2` skips DNS bruteforce only. `-P` / `--skip-puredns` skips both DNS bruteforce and DNS validation. Neither enables passive-only scanning.

## Options

| Option | Purpose |
| --- | --- |
| `-d DOMAIN` | Target domain; required |
| `-o DIRECTORY` | Results directory; required when using skip flags |
| `-s DIRECTORY_OR_SCRIPT` | SubDomz location; default: `~/SubDomz` |
| `--wordlist FILE` | Wordlist; required when DNS bruteforce is enabled |
| `--resolvers FILE` | Public DNS resolvers; default: `~/.config/puredns/resolvers.txt` |
| `--resolvers-trusted FILE` | Optional trusted DNS resolvers |
| `--dns-rate NUMBER` | Public resolver query limit per second; default: `100` |
| `--dns-rate-trusted NUMBER` | Trusted resolver query limit per second; default: `50` |
| `-r NUMBER` | HTTP requests per second for each of httpx and Katana |
| `-P` / `--skip-puredns` | Skip DNS bruteforce and DNS validation |
| `--exclude-host HOST` | Exclude a hostname and its descendants from HTTP stages; repeatable |
| `--exclude-file FILE` | Load excluded hostnames from a file, one per line |
| `--subdomains-only` | Exclude the root domain from HTTP stages |

The default HTTP scope includes the root domain and its subdomains. Redirects are disabled in httpx and Katana. Saved exclusions remain in effect when reusing a results directory.

HTTP scope rules and `-r` do not control tools launched inside SubDomz. HTTP scope rules do not control DNS queries. There is no overall scan or stage time limit; external tools retain their own request timeouts.

## Results

| File | Contents |
| --- | --- |
| `01_subdomz_raw.txt` | Collected SubDomz results |
| `01_puredns.txt` | DNS bruteforce results |
| `02_subdomains_deduped.txt` | Merged, deduplicated candidates within scope |
| `02_dns_resolved.txt` | DNS-validated candidates |
| `03_httpx_results.jsonl` | Raw structured HTTP results |
| `03_httpx_details.csv` | HTTP status, title, content type, redirect location, IP, technologies and response time |
| `03_httpx_live.txt` | Live URLs selected for crawling |
| `04_katana_urls.txt` | Deduplicated crawl URLs within scope |
| `05_split_js.txt` | JavaScript URLs |
| `05_split_pages.txt` | Page URLs |
| `05_split_other.txt` | Other resource URLs |
| `run.log` / `warnings.txt` | Pipeline log and detected issues |

HTTP details are always collected. Additional diagnostic files include `04_katana_process.log`, `04_katana_errors.log` and rejected scope entries. Keep `scan_config.json` with the results when reusing a directory.

Press **Ctrl+C twice within three seconds** to stop. Available partial results are retained.

Exit codes: `0` completed without detected issues; `1` fatal error; `2` partial or suspect results, or invalid arguments; `130` interrupted. Check the logs when output is empty or incomplete.


