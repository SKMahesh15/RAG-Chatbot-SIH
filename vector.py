from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_core.documents import Document
import os 
import pandas as pd


def none_if_nan(val):
    if val is None:
        return None
    if isinstance(val, str) and val.strip().lower() == 'nan':
        return None
    return val

df = pd.read_csv("normalized_findings.csv", dtype=str)
df.columns = [c.strip().lower() for c in df.columns]

embeddings = OllamaEmbeddings(model="mxbai-embed-large") 

db_location = "./chrome_db"
add_doc = not os.path.exists(db_location)



documents = []
ids = []

for i, r in df.iterrows():
    content = f"""Title: {r['name']} | {r['synopsis']}

        Description:
        {r['description']}

        Remediation:
        {r['solution']}

        Severity: {r['risk']}
        CVSS v3: {r['cvss_v3']}, CVSS v2: {r['cvss_v2']}, 
        VPR: {r['vpr']}, EPSS: {r['epss']}
        Host: {r['host']} Protocol: {r['protocol']} Port: {r['port']}
        """

    # Metadata (for filtering/search)
    meta = {
        "plugin_id": r['plugin_id'],
        "cve_id": None if r['cve_id'] == 'nan' else r['cve_id'],
        "cvss_v3": None if r['cvss_v3'] == 'nan' else float(r['cvss_v3']),
        "cvss_v2": None if r['cvss_v2'] == 'nan' else float(r['cvss_v2']),
        "vpr": None if r['vpr'] == 'nan' else float(r['vpr']),
        "epss": None if r['epss'] == 'nan' else float(r['epss']),
        "risk": r['risk'],
        "host": r['host'],
        "protocol": r['protocol'],
        "port": int(r['port']) if str(r['port']).isdigit() else None
    }

    doc = Document(page_content=content, metadata=meta, id=str(i))
    documents.append(doc)
    ids.append(str(i))


vector_store = Chroma(
    collection_name="vuln_findings",
    persist_directory=db_location,
    embedding_function=embeddings
)

if add_doc:
    vector_store.add_documents(documents=documents, ids=ids)

retriever = vector_store.as_retriever(search_kwargs={"k": 5})

