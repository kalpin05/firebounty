"""
FireBounty v2 - Out-of-Band (OOB) / Collaborator Utility
"""

import time
import requests
from core.config_loader import load_config
from utils.logger import log

class DNSLogClient:
    """
    Client for dnslog.cn to receive out-of-band DNS interactions without dependencies.
    """
    def __init__(self):
        self.session = requests.Session()
        self.domain = None
        self.headers = {
            "User-Agent": "FireBounty/2.0 (OOB Client)",
            "Accept": "*/*"
        }

    def register(self) -> bool:
        """
        Fetches a new domain and registers a session on dnslog.cn.
        """
        try:
            r = self.session.get("http://dnslog.cn/getdomain.php", headers=self.headers, timeout=15)
            if r.status_code == 200 and r.text.strip():
                self.domain = r.text.strip()
                log(f"[OOB] Registered DNSLog domain: {self.domain}")
                return True
        except Exception as e:
            log(f"[OOB] Error registering with DNSLog: {e}")
        return False

    def poll(self) -> list:
        """
        Polls for DNS interactions on the registered domain.
        Returns a list of dictionaries with subdomains, IPs, and timestamps.
        """
        if not self.domain:
            return []
        try:
            r = self.session.get("http://dnslog.cn/getrecords.php", headers=self.headers, timeout=15)
            if r.status_code == 200:
                try:
                    data = r.json()
                    # dnslog.cn returns list of lists: [[subdomain, ip, time], ...]
                    interactions = []
                    for item in data:
                        if len(item) >= 3:
                            interactions.append({
                                "subdomain": item[0],
                                "ip": item[1],
                                "time": item[2],
                                "type": "DNS"
                            })
                    return interactions
                except ValueError:
                    # No JSON returned or empty response
                    return []
        except Exception as e:
            log(f"[OOB] Error polling DNSLog: {e}")
        return []


class OOBManager:
    """
    Manager to coordinate OOB payload generation and polling.
    """
    def __init__(self):
        config = load_config()
        oob_cfg = config.get("oob", {})
        self.custom_url = oob_cfg.get("collaborator_url")
        self.client = None

        if not self.custom_url:
            self.client = DNSLogClient()
            self.client.register()

    def get_collaborator_domain(self) -> str:
        """
        Returns the main collaborator domain/URL base.
        """
        if self.custom_url:
            return self.custom_url
        return self.client.domain if self.client else ""

    def generate_payload(self, identifier: str) -> str:
        """
        Generates a unique payload URL to insert into target injection vectors.
        """
        base = self.get_collaborator_domain()
        if not base:
            return ""
        
        # Clean custom URLs or construct subdomains
        if self.custom_url:
            separator = "/" if not base.endswith("/") else ""
            return f"{base}{separator}{identifier}"
        else:
            return f"{identifier}.{base}"

    def poll_interactions(self) -> list:
        """
        Polls for interactions. Only works if using the default DNSLog client.
        """
        if self.client:
            return self.client.poll()
        log("[OOB] Custom collaborator URL configured; automated polling not supported for this provider.")
        return []
