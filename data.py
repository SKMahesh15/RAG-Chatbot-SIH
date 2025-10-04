import pandas as pd
import numpy as np
from datetime import datetime

def normalize_findings(nessus_csv, nikto_csv, output_csv="normalized_findings.csv"):
    """
    Reads Nessus and Nikto CSVs, normalizes data, and exports a merged CSV
    compatible for downstream RAG or ML processing.
    """

    # --- Load data ---
    df = pd.read_csv(nessus_csv, dtype=str)
    df2 = pd.read_csv(nikto_csv, dtype=str)

    out_rows = []

    # --- Normalize Nessus-style data (nessus_csv) ---
    for _, r in df.iterrows():
        try:
            cvss_v3_val = r.get('CVSS v3.0 Base Score')
            cvss_v3 = np.float32(cvss_v3_val) if cvss_v3_val not in [None, 'nan', ''] else None

            cvss_v2_val = r.get('CVSS v2.0 Base Score')
            cvss_v2 = np.float32(cvss_v2_val) if cvss_v2_val not in [None, 'nan', ''] else None

            vpr_val = r.get('VPR Score')
            vpr = np.float32(vpr_val) if vpr_val not in [None, 'nan', ''] else None

            epss_val = r.get('EPSS Score')
            epss = np.float32(epss_val) if epss_val not in [None, 'nan', ''] else None

            pub_date_str = r.get('Plugin Publication Date')
            mod_date_str = r.get('Plugin Modification Date')

            # Parse dates safely
            try:
                pub_date = datetime.strptime(pub_date_str, "%Y/%m/%d") if pd.notna(pub_date_str) else None
                mod_date = datetime.strptime(mod_date_str, "%Y/%m/%d") if pd.notna(mod_date_str) else None
            except:
                pub_date, mod_date = None, None

            today = datetime.utcnow()
            age_since_publish = (today - pub_date).days if pub_date else None
            age_since_mod = (today - mod_date).days if mod_date else None

            out = {
                "plugin_id": r.get('Plugin ID'),
                "cve_id": r.get('CVE') if r.get('CVE') not in ['nan', None, ''] else None,
                'CVSS_v2.0_base_score': cvss_v2,
                'risk': r.get('Risk'),
                'host': r.get('Host'),
                'protocol': r.get('Protocol'),
                'port': r.get('Port') if str(r.get('Port')).isdigit() else None,
                'name': r.get('Name'),
                'synopsis': r.get('Synopsis'),
                'description': r.get('Description'),
                'solution': r.get('Solution'),
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "vpr": vpr,
                "epss": epss,
                'age_days': age_since_publish,
                'core_impact': r.get('Core Impact'),
                'source': 'nessus'
            }
            out_rows.append(out)

        except Exception as e:
            print(f"[!] Error parsing Nessus row: {e}")

    # --- Normalize Nikto-style data (nikto_csv) ---
    for index, r in df2.iterrows():
        host, ip, port, _, _, description = index 
        try:
            out = {
                "plugin_id": None,
                "cve_id": None,
                "CVSS_v2.0_base_score": None,
                "risk": None,
                "host": [host, ip],
                "protocol": "HTTP",
                "port": port,
                "name": None,
                "synopsis": None,
                "description": description,
                "solution": None,
                "cvss_v3": None,
                "cvss_v2": None,
                "vpr": None,
                "epss": None,
                "age_days": None,
                "core_impact": None,
                "source": "nikto"
            }
            out_rows.append(out)

        except Exception as e:
            print(f"[!] Error parsing Nikto row: {e}")

    # --- Export ---
    out_df = pd.DataFrame(out_rows)
    out_df.to_csv(output_csv, index=False)
    print(f"✅ Normalized findings saved to: {output_csv}")

    return out_df
