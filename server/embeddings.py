"""
Embedding generation for vector matching.

Converts member projections (skills, interests, description) into
384-dimension vectors for cosine similarity matching in Postgres.

Uses the chapter agent's LLM client for embeddings. Falls back to
a simple TF-IDF-like hash embedding if the provider doesn't support
embeddings.
"""

import hashlib
import math

import httpx

_api_key = ""
_base_url = ""
EMBEDDING_DIM = 384


def init(api_key: str, base_url: str):
    global _api_key, _base_url
    _api_key = api_key
    _base_url = base_url


def _text_from_projection(projection: dict) -> str:
    """Build a searchable text from a projection's skills and interests."""
    parts = []
    skills = projection.get("skills", [])
    interests = projection.get("interests", [])
    chapter = projection.get("chapter", "")

    if skills:
        parts.append(f"skills: {', '.join(skills)}")
    if interests:
        parts.append(f"interests: {', '.join(interests)}")
    if chapter:
        parts.append(f"chapter: {chapter}")

    return " ".join(parts) if parts else "general member"


async def generate_embedding(text: str) -> list[float] | None:
    """Generate a 384-dim embedding vector from text.

    Tries the xAI/OpenAI embedding API first. Falls back to a
    deterministic hash-based embedding for portability.
    """
    # Try API-based embedding
    if _api_key and _base_url:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{_base_url.rstrip('/')}/embeddings",
                    headers={
                        "Authorization": f"Bearer {_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "text-embedding-3-small",
                        "input": text[:8000],
                    },
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    embedding = data["data"][0]["embedding"]
                    # Truncate or pad to EMBEDDING_DIM
                    if len(embedding) > EMBEDDING_DIM:
                        embedding = embedding[:EMBEDDING_DIM]
                    elif len(embedding) < EMBEDDING_DIM:
                        embedding.extend([0.0] * (EMBEDDING_DIM - len(embedding)))
                    return embedding
        except Exception as e:
            print(f"[Embeddings] API embedding failed: {e}")

    # Fallback: deterministic hash-based embedding
    return _hash_embedding(text)


def _hash_embedding(text: str) -> list[float]:
    """Generate a deterministic pseudo-embedding from text.

    Uses token hashing to create a sparse vector. Not as good as
    real embeddings but deterministic and works without an API.
    Similar texts will have similar vectors due to token overlap.
    """
    vector = [0.0] * EMBEDDING_DIM
    tokens = text.lower().split()

    for token in tokens:
        # Hash each token to a position and value
        h = hashlib.sha256(token.encode()).hexdigest()
        pos = int(h[:8], 16) % EMBEDDING_DIM
        val = (int(h[8:16], 16) % 1000) / 1000.0
        vector[pos] += val

    # Normalize to unit vector
    magnitude = math.sqrt(sum(v * v for v in vector))
    if magnitude > 0:
        vector = [v / magnitude for v in vector]

    return vector


async def embed_projection(projection: dict) -> list[float] | None:
    """Generate embedding for a member projection."""
    text = _text_from_projection(projection)
    return await generate_embedding(text)


async def embed_intent(intent_text: str, tags: list[str] | None = None) -> list[float] | None:
    """Generate embedding for an intent query."""
    text = intent_text
    if tags:
        text += f" skills: {', '.join(tags)}"
    return await generate_embedding(text)
