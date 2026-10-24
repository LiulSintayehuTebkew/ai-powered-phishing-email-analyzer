import hashlib
from pathlib import Path

import chromadb

DB_PATH = str(Path(__file__).resolve().parent / "chroma_db")
_client = chromadb.PersistentClient(path=DB_PATH)
_collection = _client.get_or_create_collection("phishing_knowledge")
_embedder = None


def _embed(text):
    """Load the embedding model on first use (keeps app start-up fast)."""
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder.encode(text).tolist()


def add_case(email_text, verdict):
    """Save an analyst decision. Same email => same id, so re-labelling replaces instead of duplicating."""
    cid = hashlib.sha256(email_text.encode("utf-8", "ignore")).hexdigest()[:24]
    _collection.upsert(ids=[cid], embeddings=[_embed(email_text)], documents=[email_text], metadatas=[{"verdict": verdict}])


def count_cases():
    return _collection.count()


def retrieve_cases(email_text, n=3):
    """Return the closest past cases as [{'text', 'verdict', 'distance'}] (empty list if the DB is empty)."""
    total = _collection.count()
    if total == 0:
        return []
    r = _collection.query(query_embeddings=[_embed(email_text)], n_results=min(n, total))
    return [{"text": d, "verdict": (m or {}).get("verdict", "unknown"), "distance": round(dist, 3)}
            for d, m, dist in zip(r["documents"][0], r["metadatas"][0], r["distances"][0])]
