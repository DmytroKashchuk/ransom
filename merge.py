"""
Entity Resolution Pipeline for Ransomware Incident Databases
=============================================================
Merges incidents across: ransomware.live, Maryland DB, VERIS, Ransomware Decade
Then enriches with 10-K filings data.

Requirements:
    pip install pandas rapidfuzz scikit-learn tqdm anthropic

Usage:
    python entity_resolution.py                     # fuzzy matching only
    python entity_resolution.py --use-llm           # + LLM disambiguation
    python entity_resolution.py --use-llm --dry-run # preview LLM candidates without API calls
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd
from rapidfuzz import fuzz, process
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from tqdm import tqdm

# ──────────────────────────────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────────────────────────────

PATHS = {
    "ransomware_live": "data2/ransomware_live.csv",
    "maryland": "data2/maryland.csv",
    "veris": "data2/veris.csv",
    "filings_10k": "data2/10k/master_records.csv",
}

# Matching thresholds
AUTO_MATCH_THRESHOLD = 90       # fuzzy score >= this → auto-match
CANDIDATE_THRESHOLD = 65        # fuzzy score >= this → candidate for LLM review
DATE_WINDOW_DAYS = 365          # incidents within this window are candidates
TFIDF_THRESHOLD = 0.45          # cosine similarity threshold for TF-IDF matching

# LLM config
LLM_MODEL = "claude-sonnet-4-20250514"
LLM_BATCH_SIZE = 20
LLM_MAX_CANDIDATES = 500        # max pairs to send to LLM (cost control)

# Output
OUTPUT_DIR = "output"

# ──────────────────────────────────────────────────────────────────────
# NORMALIZATION
# ──────────────────────────────────────────────────────────────────────

# Common suffixes/noise to strip from org names
STRIP_PATTERNS = [
    r"\b(inc|incorporated|corp|corporation|ltd|limited|llc|llp|plc|gmbh|ag|sa|srl|spa|co)\b",
    r"\b(the|of|and|for|in|at)\b",
    r"[.,;:!?'\"()\-/\\&@#]",
    r"\s+",
]

# Country name normalization map
COUNTRY_MAP = {
    "US": "US", "USA": "US", "United States": "US",
    "United States of America": "US",
    "GB": "GB", "UK": "GB", "United Kingdom": "GB",
    "Great Britain": "GB",
    "FR": "FR", "France": "FR",
    "DE": "DE", "Germany": "DE",
    "IT": "IT", "Italy": "IT",
    "ES": "ES", "Spain": "ES",
    "PT": "PT", "Portugal": "PT",
    "CA": "CA", "Canada": "CA",
    "AU": "AU", "Australia": "AU",
    "BR": "BR", "Brazil": "BR",
    "MX": "MX", "Mexico": "MX",
    "IN": "IN", "India": "IN",
    "CN": "CN", "China": "CN",
    "JP": "JP", "Japan": "JP",
}

# Sector normalization map (coarse grouping)
SECTOR_MAP = {
    # Education
    "education": "education",
    "educational": "education",
    "educational services": "education",
    "61": "education",
    # Government
    "government": "government",
    "gov": "government",
    "public administration": "government",
    "92": "government",
    # Healthcare
    "healthcare": "healthcare",
    "health care": "healthcare",
    "health": "healthcare",
    "medical": "healthcare",
    "hospitals": "healthcare",
    "62": "healthcare",
    # Finance
    "finance": "finance",
    "financial": "finance",
    "banking": "finance",
    "insurance": "finance",
    "52": "finance",
    # Manufacturing
    "manufacturing": "manufacturing",
    "31": "manufacturing", "32": "manufacturing", "33": "manufacturing",
    # IT / Technology
    "technology": "technology",
    "tech": "technology",
    "it": "technology",
    "information": "technology",
    "51": "technology",
    # Retail / Trade
    "retail": "retail",
    "trade": "retail",
    "trade & service": "retail",
    "44": "retail", "45": "retail",
}


def normalize_name(name: str) -> str:
    """Aggressively normalize an organization name for matching."""
    if not isinstance(name, str) or not name.strip():
        return ""
    s = name.lower().strip()
    for pattern in STRIP_PATTERNS:
        s = re.sub(pattern, " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def normalize_country(country) -> str:
    """Normalize country to 2-letter code."""
    if not isinstance(country, str) or not country.strip():
        return ""
    c = country.strip()
    return COUNTRY_MAP.get(c, c.upper()[:2])


def normalize_sector(sector) -> str:
    """Normalize sector/industry to coarse category."""
    if not isinstance(sector, str) or not sector.strip():
        return ""
    s = sector.lower().strip()
    # Try direct lookup
    if s in SECTOR_MAP:
        return SECTOR_MAP[s]
    # Try matching first 2 digits of NAICS/SIC codes
    code = re.match(r"^(\d{2})", s)
    if code and code.group(1) in SECTOR_MAP:
        return SECTOR_MAP[code.group(1)]
    # Try substring match
    for key, val in SECTOR_MAP.items():
        if key in s:
            return val
    return s


def extract_domain(url) -> str:
    """Extract bare domain from URL."""
    if not isinstance(url, str) or not url.strip():
        return ""
    url = url.lower().strip()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    url = url.split("/")[0].split("?")[0]
    return url


def parse_date(date_val) -> Optional[pd.Timestamp]:
    """Best-effort date parsing."""
    if pd.isna(date_val) or date_val == "":
        return None
    try:
        return pd.to_datetime(date_val, errors="coerce")
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────
# DATA LOADING & STANDARDIZATION
# ──────────────────────────────────────────────────────────────────────

@dataclass
class UnifiedRecord:
    """Standardized record across all databases."""
    source_db: str
    source_id: str
    org_name: str
    org_name_norm: str
    country: str
    country_norm: str
    sector: str
    sector_norm: str
    date: Optional[pd.Timestamp]
    year: Optional[int]
    domain: str
    description: str
    raw: dict = field(default_factory=dict, repr=False)


def load_ransomware_live(path: str) -> list[UnifiedRecord]:
    """Load and standardize ransomware.live data."""
    print(f"  Loading ransomware.live from {path}...")
    df = pd.read_csv(path, low_memory=False)
    records = []
    for i, row in df.iterrows():
        name = str(row.get("post_title", ""))
        dt = parse_date(row.get("discovered") or row.get("published"))
        records.append(UnifiedRecord(
            source_db="ransomware_live",
            source_id=f"rl_{i}",
            org_name=name,
            org_name_norm=normalize_name(name),
            country=str(row.get("country", "")),
            country_norm=normalize_country(str(row.get("country", ""))),
            sector=str(row.get("activity", "")),
            sector_norm=normalize_sector(str(row.get("activity", ""))),
            date=dt,
            year=dt.year if dt and pd.notna(dt) else None,
            domain=extract_domain(str(row.get("website", ""))),
            description=str(row.get("description", ""))[:500],
            raw=row.to_dict(),
        ))
    print(f"    → {len(records)} records")
    return records


def load_maryland(path: str) -> list[UnifiedRecord]:
    """Load and standardize Maryland DB data."""
    print(f"  Loading Maryland DB from {path}...")
    df = pd.read_csv(path, low_memory=False)
    records = []
    for i, row in df.iterrows():
        name = str(row.get("organization", ""))
        dt = parse_date(row.get("event_date"))
        year_val = row.get("year")
        yr = int(year_val) if pd.notna(year_val) else (dt.year if dt and pd.notna(dt) else None)
        records.append(UnifiedRecord(
            source_db="maryland",
            source_id=f"md_{row.get('slug', i)}",
            org_name=name,
            org_name_norm=normalize_name(name),
            country=str(row.get("country", "")),
            country_norm=normalize_country(str(row.get("country", ""))),
            sector=str(row.get("industry", "")),
            sector_norm=normalize_sector(str(row.get("industry", ""))),
            date=dt,
            year=yr,
            domain="",
            description=str(row.get("description", ""))[:500],
            raw=row.to_dict(),
        ))
    print(f"    → {len(records)} records")
    return records


def load_veris(path: str) -> list[UnifiedRecord]:
    """Load and standardize VERIS data."""
    print(f"  Loading VERIS from {path}...")
    df = pd.read_csv(path, low_memory=False)
    records = []
    for i, row in df.iterrows():
        name = str(row.get("victim_victim_id", ""))
        year_val = row.get("timeline_incident_year")
        yr = int(year_val) if pd.notna(year_val) else None
        month_val = row.get("timeline_incident_month")
        day_val = row.get("timeline_incident_day")
        dt = None
        if yr:
            m = int(month_val) if pd.notna(month_val) else 1
            d = int(day_val) if pd.notna(day_val) else 1
            try:
                dt = pd.Timestamp(year=yr, month=m, day=d)
            except Exception:
                pass
        records.append(UnifiedRecord(
            source_db="veris",
            source_id=f"veris_{row.get('incident_id', i)}",
            org_name=name,
            org_name_norm=normalize_name(name),
            country=str(row.get("victim_country", "")),
            country_norm=normalize_country(str(row.get("victim_country", ""))),
            sector=str(row.get("victim_industry", "")),
            sector_norm=normalize_sector(str(row.get("victim_industry", ""))),
            date=dt,
            year=yr,
            domain="",
            description=str(row.get("summary", ""))[:500],
            raw=row.to_dict(),
        ))
    print(f"    → {len(records)} records")
    return records


def load_ransomware_decade(path: str) -> list[UnifiedRecord]:
    """Load and standardize Ransomware Decade data."""
    print(f"  Loading Ransomware Decade from {path}...")
    df = pd.read_csv(path, low_memory=False)
    records = []
    for i, row in df.iterrows():
        name = str(row.get("victim", ""))
        dt = parse_date(row.get("incident-date"))
        rl_url = str(row.get("ransomware.live-url", ""))
        records.append(UnifiedRecord(
            source_db="ransomware_decade",
            source_id=f"rd_{row.get('uuid', i)}",
            org_name=name,
            org_name_norm=normalize_name(name),
            country="",  # not directly available, extract from sources if needed
            country_norm="",
            sector=str(row.get("sector", "")),
            sector_norm=normalize_sector(str(row.get("sector", ""))),
            date=dt,
            year=dt.year if dt and pd.notna(dt) else None,
            domain=extract_domain(rl_url) if "ransomware.live" not in rl_url else "",
            description="",
            raw=row.to_dict(),
        ))
    print(f"    → {len(records)} records")
    return records


def load_10k(path: str) -> pd.DataFrame:
    """Load 10-K filings (used for enrichment, not incident matching)."""
    print(f"  Loading 10-K filings from {path}...")
    df = pd.read_csv(path, low_memory=False)
    df["name_norm"] = df["name"].apply(lambda x: normalize_name(str(x)))
    print(f"    → {len(df)} records")
    return df


# ──────────────────────────────────────────────────────────────────────
# BLOCKING
# ──────────────────────────────────────────────────────────────────────

def generate_block_keys(rec: UnifiedRecord) -> set[str]:
    """
    Generate blocking keys to reduce pairwise comparisons.
    A record can belong to multiple blocks (increases recall).
    """
    keys = set()

    # Block 1: country + year
    if rec.country_norm and rec.year:
        keys.add(f"cy_{rec.country_norm}_{rec.year}")
        # Also allow ±1 year
        keys.add(f"cy_{rec.country_norm}_{rec.year - 1}")
        keys.add(f"cy_{rec.country_norm}_{rec.year + 1}")

    # Block 2: sector + year
    if rec.sector_norm and rec.year:
        keys.add(f"sy_{rec.sector_norm}_{rec.year}")
        keys.add(f"sy_{rec.sector_norm}_{rec.year - 1}")
        keys.add(f"sy_{rec.sector_norm}_{rec.year + 1}")

    # Block 3: first 4 chars of normalized name (catches most variants)
    if len(rec.org_name_norm) >= 4:
        keys.add(f"n4_{rec.org_name_norm[:4]}")

    # Block 4: first word of name
    first_word = rec.org_name_norm.split()[0] if rec.org_name_norm else ""
    if len(first_word) >= 3:
        keys.add(f"fw_{first_word}")

    # Block 5: domain (very high precision)
    if rec.domain:
        keys.add(f"dom_{rec.domain}")

    return keys


# ──────────────────────────────────────────────────────────────────────
# MATCHING ENGINE
# ──────────────────────────────────────────────────────────────────────

@dataclass
class MatchCandidate:
    rec_a: UnifiedRecord
    rec_b: UnifiedRecord
    name_score: float
    tfidf_score: float
    date_compatible: bool
    country_compatible: bool
    sector_compatible: bool
    domain_match: bool
    composite_score: float
    match_type: str = ""  # "auto", "llm_match", "llm_no_match", "llm_uncertain"


def compute_name_score(a: UnifiedRecord, b: UnifiedRecord) -> float:
    """Multi-strategy fuzzy name comparison."""
    if not a.org_name_norm or not b.org_name_norm:
        return 0.0
    scores = [
        fuzz.ratio(a.org_name_norm, b.org_name_norm),
        fuzz.token_sort_ratio(a.org_name_norm, b.org_name_norm),
        fuzz.token_set_ratio(a.org_name_norm, b.org_name_norm),
        fuzz.partial_ratio(a.org_name_norm, b.org_name_norm),
    ]
    # Weighted: token_set_ratio handles word reordering best
    return 0.2 * scores[0] + 0.25 * scores[1] + 0.35 * scores[2] + 0.2 * scores[3]


def check_date_compatible(a: UnifiedRecord, b: UnifiedRecord) -> bool:
    """Check if dates are within the configured window."""
    if a.date is None or b.date is None:
        return True  # can't rule it out
    try:
        delta = abs((a.date - b.date).days)
        return delta <= DATE_WINDOW_DAYS
    except Exception:
        return True


def check_country_compatible(a: UnifiedRecord, b: UnifiedRecord) -> bool:
    if not a.country_norm or not b.country_norm:
        return True  # unknown → compatible
    return a.country_norm == b.country_norm


def check_sector_compatible(a: UnifiedRecord, b: UnifiedRecord) -> bool:
    if not a.sector_norm or not b.sector_norm:
        return True
    return a.sector_norm == b.sector_norm


def check_domain_match(a: UnifiedRecord, b: UnifiedRecord) -> bool:
    if not a.domain or not b.domain:
        return False
    return a.domain == b.domain


def compute_composite_score(
    name_score: float,
    tfidf_score: float,
    date_compat: bool,
    country_compat: bool,
    sector_compat: bool,
    domain_match: bool,
) -> float:
    """
    Weighted composite score. Domain match is a very strong signal.
    """
    score = name_score * 0.50

    # TF-IDF on descriptions (if available)
    score += tfidf_score * 100 * 0.10

    # Bonuses / penalties
    if domain_match:
        score += 25  # huge bonus
    if not date_compat:
        score -= 20
    if not country_compat:
        score -= 15
    if not sector_compat:
        score -= 5
    if date_compat and country_compat and sector_compat:
        score += 5  # coherence bonus

    return min(score, 100)


def find_matches(
    records_a: list[UnifiedRecord],
    records_b: list[UnifiedRecord],
    label: str,
) -> tuple[list[MatchCandidate], list[MatchCandidate]]:
    """
    Find matching incident pairs between two record sets.
    Returns (auto_matches, llm_candidates).
    """
    print(f"\n{'='*60}")
    print(f"Matching: {label}")
    print(f"  {len(records_a)} × {len(records_b)} = {len(records_a)*len(records_b):,} potential pairs")

    # Build blocking index
    print("  Building blocking index...")
    blocks_a: dict[str, list[int]] = {}
    for i, rec in enumerate(records_a):
        for key in generate_block_keys(rec):
            blocks_a.setdefault(key, []).append(i)

    # Find candidate pairs via blocking
    candidate_pairs: set[tuple[int, int]] = set()
    for j, rec_b in enumerate(records_b):
        for key in generate_block_keys(rec_b):
            if key in blocks_a:
                for i in blocks_a[key]:
                    candidate_pairs.add((i, j))

    print(f"  Blocking reduced to {len(candidate_pairs):,} candidate pairs "
          f"({100*len(candidate_pairs)/(len(records_a)*len(records_b)+1):.2f}%)")

    if not candidate_pairs:
        return [], []

    # Precompute TF-IDF matrix for description similarity
    all_descs = [r.description for r in records_a] + [r.description for r in records_b]
    tfidf_matrix = None
    if any(d.strip() for d in all_descs):
        try:
            vec = TfidfVectorizer(max_features=5000, stop_words="english")
            tfidf_matrix = vec.fit_transform(all_descs)
        except Exception:
            pass

    # Score all candidate pairs
    auto_matches = []
    llm_candidates = []

    for i, j in tqdm(candidate_pairs, desc="  Scoring pairs"):
        rec_a = records_a[i]
        rec_b = records_b[j]

        name_score = compute_name_score(rec_a, rec_b)
        date_compat = check_date_compatible(rec_a, rec_b)
        country_compat = check_country_compatible(rec_a, rec_b)
        sector_compat = check_sector_compatible(rec_a, rec_b)
        domain_match = check_domain_match(rec_a, rec_b)

        # TF-IDF score
        tfidf_score = 0.0
        if tfidf_matrix is not None:
            try:
                idx_a = i
                idx_b = len(records_a) + j
                tfidf_score = cosine_similarity(
                    tfidf_matrix[idx_a:idx_a+1],
                    tfidf_matrix[idx_b:idx_b+1]
                )[0, 0]
            except Exception:
                pass

        composite = compute_composite_score(
            name_score, tfidf_score, date_compat,
            country_compat, sector_compat, domain_match
        )

        if composite < CANDIDATE_THRESHOLD:
            continue

        candidate = MatchCandidate(
            rec_a=rec_a,
            rec_b=rec_b,
            name_score=name_score,
            tfidf_score=tfidf_score,
            date_compatible=date_compat,
            country_compatible=country_compat,
            sector_compatible=sector_compat,
            domain_match=domain_match,
            composite_score=composite,
        )

        if composite >= AUTO_MATCH_THRESHOLD:
            candidate.match_type = "auto"
            auto_matches.append(candidate)
        else:
            llm_candidates.append(candidate)

    # Sort by score descending
    auto_matches.sort(key=lambda m: m.composite_score, reverse=True)
    llm_candidates.sort(key=lambda m: m.composite_score, reverse=True)

    print(f"  ✓ Auto-matches: {len(auto_matches)}")
    print(f"  ? LLM candidates: {len(llm_candidates)}")

    return auto_matches, llm_candidates


# ──────────────────────────────────────────────────────────────────────
# LLM DISAMBIGUATION
# ──────────────────────────────────────────────────────────────────────

LLM_PROMPT_TEMPLATE = """You are an expert at entity resolution for cybersecurity incident databases.
Determine if these two records describe the SAME real-world ransomware/cyber incident.

Record A ({source_a}):
- Organization: {name_a}
- Country: {country_a}
- Sector: {sector_a}
- Date: {date_a}
- Description: {desc_a}

Record B ({source_b}):
- Organization: {name_b}
- Country: {country_b}
- Sector: {sector_b}
- Date: {date_b}
- Description: {desc_b}

Consider:
1. Are the organization names plausibly the same entity (accounting for abbreviations, misspellings, translations)?
2. Are the dates close enough to be the same incident?
3. Do country and sector align?
4. Could descriptions refer to the same event?

Respond with EXACTLY one JSON object:
{{"verdict": "MATCH" | "NO_MATCH" | "UNCERTAIN", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}"""


def disambiguate_with_llm(
    candidates: list[MatchCandidate],
    dry_run: bool = False,
) -> list[MatchCandidate]:
    """Use Claude to disambiguate uncertain candidate pairs."""
    if not candidates:
        return []

    candidates = candidates[:LLM_MAX_CANDIDATES]
    print(f"\n  LLM disambiguation: {len(candidates)} pairs")

    if dry_run:
        print("  [DRY RUN] Would send these pairs to LLM:")
        for c in candidates[:10]:
            print(f"    {c.rec_a.org_name} ({c.rec_a.source_db}) ↔ "
                  f"{c.rec_b.org_name} ({c.rec_b.source_db}) "
                  f"[score={c.composite_score:.1f}]")
        if len(candidates) > 10:
            print(f"    ... and {len(candidates)-10} more")
        return candidates

    try:
        import anthropic
        client = anthropic.Anthropic()  # uses ANTHROPIC_API_KEY env var
    except Exception as e:
        print(f"  ⚠ Could not init Anthropic client: {e}")
        print("  Set ANTHROPIC_API_KEY env var or run with --dry-run")
        return candidates

    resolved = []
    for i in tqdm(range(0, len(candidates), LLM_BATCH_SIZE), desc="  LLM batches"):
        batch = candidates[i:i + LLM_BATCH_SIZE]

        for candidate in batch:
            a, b = candidate.rec_a, candidate.rec_b
            prompt = LLM_PROMPT_TEMPLATE.format(
                source_a=a.source_db, name_a=a.org_name,
                country_a=a.country or "Unknown", sector_a=a.sector or "Unknown",
                date_a=str(a.date)[:10] if a.date else "Unknown",
                desc_a=a.description[:300] if a.description else "N/A",
                source_b=b.source_db, name_b=b.org_name,
                country_b=b.country or "Unknown", sector_b=b.sector or "Unknown",
                date_b=str(b.date)[:10] if b.date else "Unknown",
                desc_b=b.description[:300] if b.description else "N/A",
            )

            try:
                response = client.messages.create(
                    model=LLM_MODEL,
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}],
                )
                text = response.content[0].text.strip()
                # Parse JSON from response
                json_match = re.search(r'\{.*\}', text, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                    verdict = result.get("verdict", "UNCERTAIN").upper()
                    if verdict == "MATCH":
                        candidate.match_type = "llm_match"
                    elif verdict == "NO_MATCH":
                        candidate.match_type = "llm_no_match"
                    else:
                        candidate.match_type = "llm_uncertain"
                else:
                    candidate.match_type = "llm_uncertain"
            except Exception as e:
                print(f"    ⚠ LLM error for {a.org_name} ↔ {b.org_name}: {e}")
                candidate.match_type = "llm_uncertain"

            resolved.append(candidate)
            time.sleep(0.1)  # rate limiting

    return resolved


# ──────────────────────────────────────────────────────────────────────
# 10-K ENRICHMENT
# ──────────────────────────────────────────────────────────────────────

def enrich_with_10k(
    matched_orgs: set[str],
    filings_df: pd.DataFrame,
) -> dict[str, dict]:
    """Match resolved org names against 10-K filings for enrichment."""
    print(f"\n{'='*60}")
    print("Enriching with 10-K filings data...")

    enrichment = {}
    filing_names = filings_df["name_norm"].tolist()

    for org_norm in tqdm(matched_orgs, desc="  Matching to 10-K"):
        if not org_norm:
            continue
        results = process.extract(
            org_norm, filing_names, scorer=fuzz.token_set_ratio, limit=3
        )
        if results and results[0][1] >= 85:
            idx = filing_names.index(results[0][0])
            row = filings_df.iloc[idx]
            enrichment[org_norm] = {
                "filing_name": row["name"],
                "cik": row.get("cik"),
                "total_assets": row.get("total_assets_24"),
                "size": row.get("size"),
                "sector_10k": row.get("sector"),
                "sic": row.get("sic"),
                "sic_description": row.get("sic_description"),
                "match_score": results[0][1],
            }

    print(f"  ✓ Enriched {len(enrichment)} organizations with 10-K data")
    return enrichment


# ──────────────────────────────────────────────────────────────────────
# OUTPUT
# ──────────────────────────────────────────────────────────────────────

def export_results(
    all_auto_matches: list[MatchCandidate],
    all_llm_results: list[MatchCandidate],
    enrichment: dict,
    output_dir: str,
):
    """Export match results to CSV files."""
    os.makedirs(output_dir, exist_ok=True)

    # Confirmed matches (auto + LLM confirmed)
    confirmed = all_auto_matches + [m for m in all_llm_results if m.match_type == "llm_match"]
    rows = []
    for m in confirmed:
        rows.append({
            "org_a": m.rec_a.org_name,
            "source_a": m.rec_a.source_db,
            "id_a": m.rec_a.source_id,
            "country_a": m.rec_a.country,
            "date_a": str(m.rec_a.date)[:10] if m.rec_a.date else "",
            "org_b": m.rec_b.org_name,
            "source_b": m.rec_b.source_db,
            "id_b": m.rec_b.source_id,
            "country_b": m.rec_b.country,
            "date_b": str(m.rec_b.date)[:10] if m.rec_b.date else "",
            "name_score": round(m.name_score, 1),
            "composite_score": round(m.composite_score, 1),
            "match_type": m.match_type,
            "domain_match": m.domain_match,
        })

    df_confirmed = pd.DataFrame(rows)
    path_confirmed = os.path.join(output_dir, "confirmed_matches.csv")
    df_confirmed.to_csv(path_confirmed, index=False)
    print(f"  ✓ Confirmed matches: {path_confirmed} ({len(df_confirmed)} rows)")

    # Uncertain / needs review
    uncertain = [m for m in all_llm_results if m.match_type in ("llm_uncertain", "")]
    rows_unc = []
    for m in uncertain:
        rows_unc.append({
            "org_a": m.rec_a.org_name,
            "source_a": m.rec_a.source_db,
            "org_b": m.rec_b.org_name,
            "source_b": m.rec_b.source_db,
            "composite_score": round(m.composite_score, 1),
            "name_score": round(m.name_score, 1),
        })
    df_uncertain = pd.DataFrame(rows_unc)
    path_uncertain = os.path.join(output_dir, "needs_review.csv")
    df_uncertain.to_csv(path_uncertain, index=False)
    print(f"  ? Needs review: {path_uncertain} ({len(df_uncertain)} rows)")

    # Rejected by LLM
    rejected = [m for m in all_llm_results if m.match_type == "llm_no_match"]
    rows_rej = []
    for m in rejected:
        rows_rej.append({
            "org_a": m.rec_a.org_name,
            "source_a": m.rec_a.source_db,
            "org_b": m.rec_b.org_name,
            "source_b": m.rec_b.source_db,
            "composite_score": round(m.composite_score, 1),
        })
    df_rejected = pd.DataFrame(rows_rej)
    path_rejected = os.path.join(output_dir, "rejected_pairs.csv")
    df_rejected.to_csv(path_rejected, index=False)
    print(f"  ✗ Rejected: {path_rejected} ({len(df_rejected)} rows)")

    # 10-K enrichment
    if enrichment:
        df_enrich = pd.DataFrame.from_dict(enrichment, orient="index")
        df_enrich.index.name = "org_name_norm"
        path_enrich = os.path.join(output_dir, "10k_enrichment.csv")
        df_enrich.to_csv(path_enrich)
        print(f"  📊 10-K enrichment: {path_enrich} ({len(df_enrich)} rows)")

    # Summary stats
    summary = {
        "total_confirmed_matches": len(confirmed),
        "auto_matches": len(all_auto_matches),
        "llm_confirmed": len([m for m in all_llm_results if m.match_type == "llm_match"]),
        "llm_rejected": len(rejected),
        "needs_review": len(uncertain),
        "orgs_with_10k_data": len(enrichment),
    }
    path_summary = os.path.join(output_dir, "summary.json")
    with open(path_summary, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  📋 Summary: {path_summary}")
    for k, v in summary.items():
        print(f"    {k}: {v}")


# ──────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Entity Resolution for Ransomware DBs")
    parser.add_argument("--use-llm", action="store_true", help="Use LLM for ambiguous pairs")
    parser.add_argument("--dry-run", action="store_true", help="Preview LLM candidates without API calls")
    parser.add_argument("--output", default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--data-dir", default=".", help="Base directory for data paths")
    args = parser.parse_args()

    print("=" * 60)
    print("ENTITY RESOLUTION PIPELINE")
    print("=" * 60)

    # Resolve paths relative to data-dir
    paths = {k: os.path.join(args.data_dir, v) for k, v in PATHS.items()}

    # Check which files exist
    available = {}
    for key, path in paths.items():
        if os.path.exists(path):
            available[key] = path
        else:
            print(f"  ⚠ Missing: {path} (skipping {key})")

    if len(available) < 2:
        print("ERROR: Need at least 2 databases to match. Check your paths.")
        sys.exit(1)

    # Load databases
    print(f"\n{'='*60}")
    print("Loading databases...")
    datasets: dict[str, list[UnifiedRecord]] = {}

    loaders = {
        "ransomware_live": load_ransomware_live,
        "maryland": load_maryland,
        "veris": load_veris,
        "ransomware_decade": load_ransomware_decade,
    }

    for key, loader in loaders.items():
        if key in available:
            try:
                datasets[key] = loader(available[key])
            except Exception as e:
                print(f"  ⚠ Error loading {key}: {e}")

    # Load 10-K separately (enrichment only)
    filings_df = None
    if "filings_10k" in available:
        try:
            filings_df = load_10k(available["filings_10k"])
        except Exception as e:
            print(f"  ⚠ Error loading 10-K: {e}")

    # Pairwise matching across all database pairs
    db_names = list(datasets.keys())
    all_auto_matches = []
    all_llm_candidates = []

    for i in range(len(db_names)):
        for j in range(i + 1, len(db_names)):
            name_a, name_b = db_names[i], db_names[j]
            label = f"{name_a} ↔ {name_b}"
            auto, llm_cands = find_matches(
                datasets[name_a], datasets[name_b], label
            )
            all_auto_matches.extend(auto)
            all_llm_candidates.extend(llm_cands)

    # LLM disambiguation
    all_llm_results = []
    if args.use_llm and all_llm_candidates:
        all_llm_results = disambiguate_with_llm(
            all_llm_candidates, dry_run=args.dry_run
        )
    elif all_llm_candidates:
        print(f"\n  ℹ {len(all_llm_candidates)} ambiguous pairs could benefit from LLM review.")
        print("    Run with --use-llm to disambiguate them.")
        all_llm_results = all_llm_candidates

    # 10-K enrichment
    all_confirmed = all_auto_matches + [m for m in all_llm_results if m.match_type == "llm_match"]
    matched_orgs = set()
    for m in all_confirmed:
        matched_orgs.add(m.rec_a.org_name_norm)
        matched_orgs.add(m.rec_b.org_name_norm)
    # Also add all unique orgs for enrichment
    for ds in datasets.values():
        for rec in ds:
            matched_orgs.add(rec.org_name_norm)

    enrichment = {}
    if filings_df is not None:
        enrichment = enrich_with_10k(matched_orgs, filings_df)

    # Export
    print(f"\n{'='*60}")
    print("Exporting results...")
    export_results(all_auto_matches, all_llm_results, enrichment, args.output)

    print(f"\n{'='*60}")
    print("Done!")


if __name__ == "__main__":
    main()