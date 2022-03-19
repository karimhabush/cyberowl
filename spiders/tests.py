import unittest
import requests
from spiders.CISASpider import CisaSpider
from spiders.CertFrSpider import CertFrSpider
from spiders.DgssiSpider import DgssiSpider
from spiders.IBMcloudSpider import IBMCloudSpider
from spiders.ZDISpider import ZDISpider


class DummyTestForNow(unittest.TestCase):
    def setUp(self):
        self.CISA_response = requests.get('https://www.cisa.gov/uscert/ncas/current-activity').status_code
        self.CertFR_response = requests.get('https://www.cert.ssi.gouv.fr').status_code
        self.MaCert_response = requests.get('https://www.dgssi.gov.ma/fr/macert/bulletins-de-securite.html').status_code
        self.IBM_cloud_response = requests.get('https://exchange.xforce.ibmcloud.com/activity/list?filter=Vulnerabilities').status_code
        self.ZDI_response = requests.get('https://www.zerodayinitiative.com/advisories/published/').status_code

    def test_if_source_not_down(self):
        self.assertEqual(self.CISA_response, 200)
        self.assertEqual(self.CertFR_response, 200)
        self.assertEqual(self.MaCert_response, 200)
        self.assertEqual(self.IBM_cloud_response, 200)
        self.assertEqual(self.ZDI_response, 200)
