from parse_zap import zap

TEXT = "#text"
SELECTED_CONFIG = []
KEY = "@key"
CVE_PATTERN = "\w\w\w-\d\d\d\d-\d\d\d\d\d"
results = []
results_cve = []
ZAP_RAW_RESULTS = "test_results/zap_raw_results_test.json"
ZAP_PROCESSED_RESULTS = "test_results/zap_processed_results_test.json"
ZAP_PROCESSED_RESULTS_CSV = "test_results/zap_processed_results_test.csv"
elements = {"blah": "blah"}
cves_list = ["blah", "blah"]

zap_instance = zap()
zap_instance.process_results(
    ZAP_RAW_RESULTS, ZAP_PROCESSED_RESULTS, ZAP_PROCESSED_RESULTS_CSV
)


def test_extract_info_cve(mocker):

    mocker.patch("parse_zap.zap.extract_info_cve", return_value=None)
    zap_instance.extract_info_cve(elements, cves_list)
    zap_instance.extract_info_cve.assert_called_once_with(elements, cves_list)


def test_load_config(mocker):

    mocker.patch("parse_zap.zap.load_config", return_value=None)
    zap_instance.load_config()
    zap_instance.load_config.assert_called_once()
