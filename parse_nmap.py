import argparse
import json
import logging
import sys
import xml

import logging_loki
import pandas as pd
import xmltodict

import config

parser = argparse.ArgumentParser(description="Configure Nmap")

USE_ZAP_RISK = False
USE_CVSS_RISK = True
ZAP_RISK_CODE_THRESHOLD = 1

parser.add_argument(
    "--CVSS_SCORE_THRESHOLD",
    type=int,
    metavar="CTHR",
    help="The CVSS score threshold. (0-10)",
)
parser.add_argument(
    "--INCLUDE_NON_EXPLOIT",
    metavar="INE",
    action=argparse.BooleanOptionalAction,
    help="Include non-exploitable vulns?. (True or False)",
)
parser.add_argument(
    "--LOKI_URL",
    metavar="LOKI",
    type=str,
    default="http://localhost:3100/loki/api/v1/push",
    help="LOKI's url E.G: http://192.168.1.1",
)

logging.basicConfig(level=logging.DEBUG)
TEXT = "#text"
SELECTED_CONFIG = []
NMAP_RAW_RESULTS_XML = "/RESULTS/nmap_raw_results.xml"
NMAP_RAW_RESULTS_JSON = "/RESULTS/nmap_raw_results.json"
NMAP_RESULTS = "/RESULTS/nmap_processed_results.json"
NMAP_RESULTS_CSV = "/RESULTS/nmap_processed_results.csv"

KEY = "@key"


class nmap:
    def __init__(self):
        self.cvss_score_threshold = None
        self.include_non_exploit = None
        self.results = []
        self.logger = logging.getLogger("nmap-petusawo-logger")

    def load_config(self, args: argparse):
        """Load Configuration"""

        if len(sys.argv) < 1:
            self.cvss_score_threshold = config.CVSS_SCORE_THRESHOLD
            self.include_non_exploit = config.INCLUDE_NON_EXPLOIT
            self.handler = logging_loki.LokiHandler(
                url="http://localhost:3100/loki/api/v1/push",
                tags={"application": "nmap"},
                version="1",
            )
            self.logger.addHandler(self.handler)
        else:
            self.cvss_score_threshold = args.CVSS_SCORE_THRESHOLD
            self.include_non_exploit = args.INCLUDE_NON_EXPLOIT
            self.handler = logging_loki.LokiHandler(
                url=args.LOKI_URL,
                tags={"application": "nmap"},
                version="1",
            )
            self.logger.addHandler(self.handler)
        logging.info("outputting configs: ")
        logging.info("self.cvss_score_threshold %s", self.cvss_score_threshold)
        logging.info("self.cvss_score_threshold %s", self.cvss_score_threshold)

    def convert_xml_to_dict(
        self, nmap_raw_results_xml: xml, nmap_raw_results_json: json
    ):
        """Convert nmap xml to JSON"""
        try:
            with open(nmap_raw_results_xml) as xml_file:
                data_dict = xmltodict.parse(xml_file.read())
                xml_file.close()
                json_data = json.dumps(data_dict)
                with open(nmap_raw_results_json, "w") as json_file:
                    json_file.write(json_data)
                    json_file.close()
        except FileNotFoundError as e:
            logging.debug(e)
            sys.exit(1)

    def extract_info_list(self, elements: list, port_info: dict):
        """Extract Important Info"""
        result = {"CVE": [], "TYPE": [], "CVSS SCORE": []}

        i = 0
        while i < 4:

            if elements[i][KEY] == "cvss":
                cvss = i
            if elements[i][KEY] == "type":
                type_ = i
            if elements[i][KEY] == "id":
                cve = i
            i += 1

        if float(elements[cvss]["#text"]) > self.cvss_score_threshold:
            result["CVE"].append(elements[cve][TEXT])
            result["TYPE"].append(elements[type_][TEXT])
            result["CVSS SCORE"].append(elements[cvss][TEXT])
            if result["CVE"]:
                self.results.append(result)
                self.logger.info(
                    result,
                    extra={"tags": {"service": "nmap"}},
                )

    def extract_info_dict(self, elements: dict, port_info: dict):
        """Extract Important Info"""
        result = {"CVE": [], "TYPE": [], "CVSS SCORE": []}
        result["PORT INFO"].append(port_info)
        i = 0
        while i < 4:
            print(elements[i][KEY])
            if elements[i][KEY] == "cvss":
                cvss = i
            if elements[i][KEY] == "type":
                type_ = i
            if elements[i][KEY] == "id":
                cve = i
            i += 1

        if float(elements[cvss]["#text"]) > self.cvss_score_threshold:
            result["CVE"].append(elements[cve][TEXT])
            result["TYPE"].append(elements[type_][TEXT])
            result["CVSS SCORE"].append(elements[cvss][TEXT])

        if result["CVE"]:
            self.results.append(result)
            self.logger.info(
                result,
                extra={"tags": {"service": "nmap"}},
            )

    def process_results(
        self, nmap_raw_results_json: json, nmap_results: json, nmap_results_csv: pd
    ) -> None:
        """Process the results"""

        f = open(nmap_raw_results_json)
        data = json.load(f)

        # get the ports, vulnerability results are attached to ports
        # 0 <elem key="is_exploit">false</elem>
        # 1 <elem key="cvss">7.5</elem>
        # 2 <elem key="type">cve</elem>
        # 3 <elem key="id">CVE-2022-31813</elem>
        for item in data["nmaprun"]["host"]["ports"]["port"]:
            if item == "script":
                logging.debug("Vulnerabilities found")
                # print(type(data["nmaprun"]["host"]["ports"]["port"][item]))
                if isinstance(data["nmaprun"]["host"]["ports"]["port"][item], list):
                    logging.debug("this is a list, handling like a list")
                    for element in data["nmaprun"]["host"]["ports"]["port"][item]:
                        if "table" in element:
                            logging.debug("table found")
                            for table in element["table"]["table"]:

                                i = 0
                                while i < 4:
                                    # if vulnerabilities which have no exploits should be included
                                    if table["elem"][i][KEY] == "is_exploit":
                                        logging.debug("found exploit")
                                        if (
                                            self.include_non_exploit is False
                                            and table["elem"][i][TEXT] == "False"
                                        ):
                                            logging.debug(
                                                "skipping because we are not including non-exploits"
                                            )
                                            i += 1
                                        else:
                                            # Check if vulnerabilities pass the threshold set in the config file
                                            logging.debug("extracting list info")
                                            self.extract_info_list(
                                                table["elem"],
                                                data["nmaprun"]["host"]["ports"][
                                                    "port"
                                                ],
                                            )
                                    i += 1
                else:
                    try:
                        for element in data["nmaprun"]["host"]["ports"]["port"][item]:
                            if type(element) is dict:
                                logging.info("type is dict, treating it as such")
                                # if vulnerabilities which have no exploits should be included
                                i = 0
                                while i < 4:
                                    if element["elem"][i][KEY] == "is_exploit":
                                        if (
                                            self.include_non_exploit is False
                                            and element["elem"][i][TEXT] == "false"
                                        ):
                                            logging.debug(
                                                "skipping because we are not including non-exploits"
                                            )
                                            i += 1
                                        else:
                                            logging.debug("extracting dict info")
                                            self.extract_info_dict(
                                                element["elem"],
                                                data["nmaprun"]["host"]["ports"][
                                                    "port"
                                                ][0],
                                            )
                                            i += 1

                    except TypeError:
                        sys.exit(1)
        logging.info("printing out results......................................")
        logging.info(self.results)

        df = pd.DataFrame(self.results)
        df.to_csv(nmap_results_csv)
        with open(nmap_results, "w") as json_file:
            json.dump(self.results, json_file)


if __name__ == "__main__":
    args = parser.parse_args()
    nmap_instance = nmap()
    nmap_instance.convert_xml_to_dict(NMAP_RAW_RESULTS_XML, NMAP_RAW_RESULTS_JSON)
    nmap_instance.load_config(args)
    nmap_instance.process_results(NMAP_RAW_RESULTS_JSON, NMAP_RESULTS, NMAP_RESULTS_CSV)
