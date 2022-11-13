# PETUSAWO

The purpose of the project is to:
- Remove clutter from vulnerability scans
- Track a target's vulnerability over time using grafana dashboards
  

## Supported Open Source Applications

- OWASP Zap
- NMAP
  
## Getting Started

### Dependencies

- Docker

### Configuration

Both ZAP and NMAP can be configured from the command line. The following are the configuration
options:

- INCLUDE_NON_EXPLOIT : If this options is set to False, NMAP will not include a vulnerability that has no known exploits
- CVSS_SCORE_THRESHOLD : The results will only contain vulnerabilities with CVSS scores greater than
  this threshold.
- USE_ZAP_RISK: This option allows you to use the native ZAP risk rating as a threshold instead of the CVSS SCORE
- USE_CVSS_RISK: This option allows you to include the native CVSS risk rating instead of the native ZAP risk rating
- ZAP_RISK_CODE_THRESHOLD: If USE_ZAP_RISK is set to True, results will only contain vulnerabilities whose ZAP RISK CODE score is greater than this value.
- LOK_URL: The url of the loki instance to push logs to

You should either use ZAP's risk score or CVSS's score, not both

## Starting Grafana and Loki

Grafana and Loki can be brought up using the following commands:

```bash
docker-compose -f grafana-loki-docker-compose.yml up -d
```

You can access grafana at https://localhost:3100

### Executing the docker image

To run zap against a url, run the following command, replacing the url with the target url.
The results will be outputted to whatever directory you specify.

```bash
docker run -v "$(pwd)":/RESULTS berryliumsec/petusawo:latest \
zap_vuln_scan https://yourtarget.com/ --USE_CVSS_RISK --CVSS_SCORE_THRESHOLD=0 --LOKI_URL="http://localhost:3100/loki/api/v1/push"
```

Example of running NMAP's vulnerability scan against an IP address:

```bash
docker run -v "$(pwd)":/RESULTS berryliumsec/petusawo:latest \
nmap_vuln_scan 000.00.000.000 \
--INCLUDE_NON_EXPLOIT --CVSS_SCORE_THRESHOLD=0 --LOKI_URL="http://localhost:3100/loki/api/v1/push"
```

### Help

To print out help files for both zap do:

```bash
docker run -v "$(pwd)":/RESULTS berryliumsec/petusawo:latest nmap_help
```

```bash
docker run -v "$(pwd)":/RESULTS berryliumsec/petusawo:latest zap_help
```

If you are not getting any results from zap, consider using the CVSS risk
score or the ZAP_RISK depending on which one isn't working.

If you are not getting any results fom nmap, there were probably no vulnerabilities
found based on the open ports.

### Output Files

Both Zap and NMAP generate a report file in JSON format. These files can be further processed by
other applications. The python library pyjsonviewer can be used to quickly inspect results: For
example:

```bash
pyjsonviewer -f zap_results.json
```
