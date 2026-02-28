import os
import hashlib
import lightgbm as lgb
import requests
from ioc_writer import ioc_api

# Monkeypatch newer signify versions to support thrember,
# circumventing the crash with oscrypto on Streamlit Cloud Python 3.13
try:
    import signify.authenticode
    if not hasattr(signify.authenticode, 'SignedPEFile'):
        class MockPE(getattr(signify.authenticode, 'AuthenticodeFile', object)):
            def __init__(self, *args, **kwargs):
                pass
            def iter_signed_datas(self):
                return iter([])
        setattr(signify.authenticode, 'SignedPEFile', MockPE)
except ImportError:
    pass

from thrember import PEFeatureExtractor

class Scanner:
    def __init__(self, model_path="models/EMBER2024_PE.model"):
        self.model_path = model_path
        self.lgbm_model = None
        self.extractor = PEFeatureExtractor()
        self.load_model()
        
    def load_model(self):
        if not os.path.exists(self.model_path):
            print(f"Model file {self.model_path} not found. Downloading EMBER2024_PE.model...")
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            try:
                from huggingface_hub import hf_hub_download
                import shutil
                # thrember actually uses this undocumented repo
                downloaded_path = hf_hub_download(repo_id="joyce8/EMBER2024-benchmark-models", filename="EMBER2024_PE.model")
                shutil.copy2(downloaded_path, self.model_path)
            except Exception as e:
                print(f"Failed to download model: {e}")
            
        if os.path.exists(self.model_path):
            self.lgbm_model = lgb.Booster(model_file=self.model_path)
        else:
            print(f"Warning: Model file {self.model_path} not found even after download attempt.")
            
    def get_hashes(self, file_data):
        md5 = hashlib.md5(file_data).hexdigest()
        sha1 = hashlib.sha1(file_data).hexdigest()
        sha256 = hashlib.sha256(file_data).hexdigest()
        return md5, sha1, sha256

    def predict(self, file_data):
        if self.lgbm_model is None:
            raise ValueError("Model is not loaded.")
        
        # Extract features
        features = self.extractor.feature_vector(file_data)
        
        # Predict
        score = self.lgbm_model.predict([features])[0]
        return score

    def check_virustotal(self, sha256, api_key):
        if not api_key:
            return {"error": "No API Key provided."}
            
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                # Extract additional IOCs if file is malicious (stats['malicious'] > 0 can be checked by caller)
                extracted_iocs = {
                    "names": attributes.get("names", []),
                    "network_iocs": [],
                    "dropped_files": []
                }
                
                # In VirusTotal API v3, relations like contacted_ips, contacted_domains need separate relationship queries
                # However, sometimes they are embedded or tags hint at them. For a basic implementation, we will fetch the 
                # behaviors/contacted_ips relationships if requested. To keep it simple in one request, we rely on the 
                # basic file attributes. If full behavior is needed, we'd make a separate call to /files/{id}/contacted_ips.
                # Let's do a quick query for contacted domains to enrich the IOC if the primary call succeeds.
                
                try:
                    rel_url = f"https://www.virustotal.com/api/v3/files/{sha256}/contacted_urls"
                    rel_resp = requests.get(rel_url, headers=headers)
                    if rel_resp.status_code == 200:
                        rel_data = rel_resp.json()
                        for item in rel_data.get("data", []):
                            if "url" in item.get("attributes", {}):
                                extracted_iocs["network_iocs"].append({"type": "url", "value": item["attributes"]["url"]})
                                
                    rel_url_domain = f"https://www.virustotal.com/api/v3/files/{sha256}/contacted_domains"
                    rel_resp_domain = requests.get(rel_url_domain, headers=headers)
                    if rel_resp_domain.status_code == 200:
                        rel_data_domain = rel_resp_domain.json()
                        for item in rel_data_domain.get("data", []):
                            domain = item.get("id") # Domain name is usually the ID in this relation
                            if domain:
                                extracted_iocs["network_iocs"].append({"type": "domain", "value": domain})
                                
                    rel_url_ip = f"https://www.virustotal.com/api/v3/files/{sha256}/contacted_ips"
                    rel_resp_ip = requests.get(rel_url_ip, headers=headers)
                    if rel_resp_ip.status_code == 200:
                        rel_data_ip = rel_resp_ip.json()
                        for item in rel_data_ip.get("data", []):
                            ip = item.get("id")
                            if ip:
                                extracted_iocs["network_iocs"].append({"type": "ip", "value": ip})
                except Exception as e:
                    print(f"Failed to fetch extended VT relations: {e}")
                    
                return {"stats": stats, "iocs": extracted_iocs}
            elif response.status_code == 404:
                return {"message": "File not found on VirusTotal."}
            else:
                return {"error": f"API Error {response.status_code}: {response.text}"}
        except Exception as e:
            return {"error": str(e)}

    def generate_ioc(self, file_name, hashes, vt_data, output_dir="."):
        md5, sha1, sha256 = hashes
        
        ioc = ioc_api.IOC(description=f"Detection of malicious file: {file_name}")
        
        # Primary File Hashes
        ioc_item = ioc_api.make_indicatoritem_node("is", "FileItem", "FileItem/Hashes/MD5", "string", md5)
        ioc.top_level_indicator.append(ioc_item)
        
        ioc_item = ioc_api.make_indicatoritem_node("is", "FileItem", "FileItem/Hashes/SHA1", "string", sha1)
        ioc.top_level_indicator.append(ioc_item)
        
        ioc_item = ioc_api.make_indicatoritem_node("is", "FileItem", "FileItem/Hashes/SHA256", "string", sha256)
        ioc.top_level_indicator.append(ioc_item)
        
        ioc_item = ioc_api.make_indicatoritem_node("contains", "FileItem", "FileItem/FileName", "string", file_name)
        ioc.top_level_indicator.append(ioc_item)
        
        # Extended IOCs from VirusTotal
        if vt_data and "iocs" in vt_data:
            iocs = vt_data["iocs"]
            
            # Alternative names
            for name in iocs.get("names", []):
                if name != file_name:
                    item = ioc_api.make_indicatoritem_node("contains", "FileItem", "FileItem/FileName", "string", name)
                    ioc.top_level_indicator.append(item)
                    
            # Network IOCs
            for net_ioc in iocs.get("network_iocs", []):
                val = net_ioc["value"]
                if net_ioc["type"] == "url":
                    # For URLs, use NetworkURI
                    item = ioc_api.make_indicatoritem_node("contains", "NetworkURI", "NetworkURI/URI", "string", val)
                    ioc.top_level_indicator.append(item)
                elif net_ioc["type"] == "domain":
                    item = ioc_api.make_indicatoritem_node("contains", "NetworkURI", "NetworkURI/Host", "string", val)
                    ioc.top_level_indicator.append(item)
                elif net_ioc["type"] == "ip":
                    item = ioc_api.make_indicatoritem_node("is", "PortItem", "PortItem/remoteIP", "IP", val)
                    ioc.top_level_indicator.append(item)
        
        # Save to file
        ioc.write_ioc_to_file(output_dir)
        output_path = os.path.join(output_dir, f"{ioc.iocid}.ioc")
        
        # Optionally rename it to the sha256 to match the UI expectation, or just let it use iocid.
        # But since app.py downloads it and sets its own filename or expects the path, we can rename it:
        desired_path = os.path.join(output_dir, f"{sha256}.ioc")
        if os.path.exists(desired_path):
            os.remove(desired_path)
        os.rename(output_path, desired_path)
        return desired_path
