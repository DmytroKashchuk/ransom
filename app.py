from flask import Flask, render_template, jsonify, request
from markupsafe import Markup
from datetime import datetime
import os, json, math, subprocess, ast, re
import numpy as np
import pandas as pd
import markdown

app = Flask(__name__)
# Intro page rendering README.md
@app.route('/intro')
def intro_page():
    readme_path = os.path.join(app.root_path, 'README.md')
    html_content = ''
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            md_text = f.read()
            # Convert markdown to HTML (safe mode removed in modern markdown lib; we trust local file)
            html_content = markdown.markdown(md_text, extensions=['extra', 'toc', 'tables', 'fenced_code'])
    except Exception as e:
        html_content = f"<p style='color:red;'>Failed to load README.md: {e}</p>"
    return render_template('intro.html', readme_html=Markup(html_content))

# Path to the CSV file
CSV_PATH = 'data/ransomed_domains_in_swdb_with_accounts.csv'
RANSOMWARE_LIVE_URL = "https://data.ransomware.live/victims.csv"
HTTP_ARCHIVE_TECH_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'bq-results-municipalities_grouped_tech_cat_ver.csv'
)
HTTP_ARCHIVE_TECH_NO_ROOT_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'bq-results-municipalities_grouped_tech_cat_ver_excluding_root_page.csv'
)
HTTP_ARCHIVE_TECH_NO_ROOT_V2_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'bq-results-municipalities_grouped_tech_cat_ver_excluding_root_page_v2.csv'
)
HTTP_ARCHIVE_MUNI_TECH_RAW_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'bq-results-municipalities_5months_before_and_after_continued.csv'
)
HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'bq-results-municipalities_5months_before_and_after_continued_reduced_by_dropping_root_page.csv'
)
HTTP_ARCHIVE_MUNI_JACCARD_ATTACK_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'muni_tech_jaccard_similarity_attack.csv'
)
HTTP_ARCHIVE_MUNI_ADDED_DROPPED_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'muni_tech_added_dropped.csv'
)
HTTP_ARCHIVE_MUNI_ADDED_DROPPED_3RD_CSV = os.path.join(
    app.root_path,
    'data',
    'http_archive',
    'muni_tech_added_dropped_3rd_month.csv'
)
HTTP_ARCHIVE_MERGED_TECH_BY_DOMAIN_CSV = os.path.join(
    app.root_path,
    'data',
    'merged_technologies_by_domain.csv'
)


def _format_size(num_bytes):
    if num_bytes is None:
        return None
    try:
        num = float(num_bytes)
    except (TypeError, ValueError):
        return None
    if num < 0:
        return None
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    for unit in units:
        if num < 1024 or unit == units[-1]:
            if unit == 'B':
                return f"{int(num)} {unit}"
            return f"{num:.2f} {unit}"
        num /= 1024
    return f"{num:.2f} PB"


def _clean_for_json(value):
    if value is None:
        return None
    if isinstance(value, (np.generic,)):
        try:
            value = value.item()
        except Exception:
            value = float(value)
    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return float(value)
    if isinstance(value, (int, str, bool)):
        return value
    if isinstance(value, dict):
        return {k: _clean_for_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean_for_json(v) for v in value]
    try:
        return value if json.dumps(value) else str(value)
    except Exception:
        return str(value)


def _parse_tech_cat_ver(value):
    if not isinstance(value, str) or not value.strip():
        return []
    items = []
    for raw in value.split(';'):
        token = raw.strip()
        if not token:
            continue
        parts = token.split('-')
        if len(parts) >= 3:
            name, category = parts[0].strip(), parts[1].strip()
            version = '-'.join(parts[2:]).strip() or None
        elif len(parts) == 2:
            name, category = parts[0].strip(), parts[1].strip()
            version = None
        else:
            name, category, version = token, None, None
        items.append({
            'name': name or None,
            'category': category or None,
            'version': version,
        })
    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for item in items:
        key = (item.get('name'), item.get('category'), item.get('version'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _safe_datetime(val):
    if val is None:
        return None
    try:
        return datetime.fromisoformat(str(val))
    except Exception:
        try:
            return datetime.strptime(str(val), '%Y-%m-%d')
        except Exception:
            return None

@app.route('/')
def index():
    return render_template('index.html')


def _ransomware_live_path():
    """Return the existing ransomware live CSV path, preferring typo file name for compatibility."""
    candidates = [
        os.path.join(app.root_path, 'data', 'ransomware_live.csv'),
        os.path.join(app.root_path, 'data', 'ranomware_live.csv'),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None


def _file_mtime_iso(path):
    try:
        ts = os.path.getmtime(path)
        return datetime.fromtimestamp(ts).isoformat()
    except Exception:
        return None

# New page: SWDB domains overview
@app.route('/swdb')
def swdb_page():
    return render_template('swdb.html')

# New page: Unique SWDB Domains (aggregated)
@app.route('/swdb_unique')
def swdb_unique_page():
    return render_template('swdb_unique.html')


@app.route('/swdb_preview_usa')
def swdb_preview_usa_page():
    return render_template('swdb_preview_usa.html')


@app.route('/api/data')
def get_data():
    """API endpoint to serve the CSV data as JSON"""
    try:
        df = pd.read_csv(CSV_PATH)

        # Merge site_ids from the secondary CSV so the client can compute unique site IDs on filtered data
        secondary_csv = 'data/ransomed_domains_in_swdb.csv'
        if os.path.exists(secondary_csv):
            try:
                df_sites = pd.read_csv(secondary_csv)
                # keep only url + site_ids and de-duplicate by url
                if {'url', 'site_ids'}.issubset(df_sites.columns):
                    df_sites = df_sites[['url', 'site_ids']].drop_duplicates(subset=['url'])
                    df = df.merge(df_sites, on='url', how='left')
            except Exception:
                # proceed without site_ids if merge fails
                pass

        # Replace NaN/Inf values with None for better JSON serialization
        df = df.replace([float('inf'), -float('inf')], pd.NA)
        df = df.where(pd.notnull(df), None)
        data = df.to_dict('records')
        # Defensive: ensure no NaN remains
        safe = []
        for rec in data:
            for k,v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            safe.append(rec)
        return app.response_class(json.dumps(safe, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API for SWDB domains CSV
@app.route('/api/swdb')
def get_swdb_data():
    try:
        swdb_path = 'data/ransomed_domains_in_swdb.csv'
        df = pd.read_csv(swdb_path)
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API for unique SWDB domains CSV (domains_swdb_unique.csv)
@app.route('/api/swdb_unique')
def get_swdb_unique_data():
    try:
        unique_path = os.path.join(app.root_path, 'data', 'domains_swdb_unique.csv')
        if not os.path.exists(unique_path):
            return jsonify({'error': f'File not found: {unique_path}'}), 404
        df = pd.read_csv(unique_path)
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load unique domains CSV: {e}'}), 500


@app.route('/api/swdb_preview_usa')
def get_swdb_preview_usa():
    """Return a flattened view of the SWDB USA preview JSON for Tabulator."""
    try:
        preview_path = os.path.join(app.root_path, 'data', 'swdb', 'swdb_preview_usa.json')
        if not os.path.exists(preview_path):
            return jsonify({'error': f'File not found: {preview_path}'}), 404

        with open(preview_path, 'r', encoding='utf-8') as handle:
            raw_payload = json.load(handle)

        records = []
        column_names = set()

        for collection_name, meta in raw_payload.items():

            if not isinstance(meta, dict):
                continue

            files = meta.get('files', {}) or {}
            collection_path = meta.get('path')
            file_count = meta.get('file_count')

            for file_label, file_info in files.items():
                if not isinstance(file_info, dict):
                    continue

                record = {
                    'collection': collection_name,
                    'collection_path': collection_path,
                    'collection_file_count': file_count,
                    'file_label': file_label,
                }

                country = None
                year = None
                if isinstance(collection_name, str) and '_' in collection_name:
                    parts = collection_name.split('_', 1)
                    country = parts[0] or None
                    potential_year = parts[1]
                    if potential_year and potential_year.isdigit():
                        year = potential_year
                elif isinstance(collection_name, str):
                    # fallback: attempt to extract trailing digits
                    digits = ''.join(ch for ch in collection_name if ch.isdigit())
                    if digits:
                        year = digits

                if country:
                    record['collection_country'] = country
                if year:
                    record['collection_year'] = year

                for key, value in file_info.items():
                    if key == 'head_lines' and isinstance(value, list):
                        record[key] = '\n'.join(value)
                    else:
                        record[key] = value

                size_bytes = record.get('size_bytes')
                record['size_human'] = _format_size(size_bytes)

                preview_rows = record.get('rows')
                if isinstance(preview_rows, list):
                    record['preview_line_count'] = len(preview_rows)
                else:
                    record['preview_line_count'] = 0

                # Provide a simplified file name for filtering
                record.setdefault('file_name', record.get('path_rel') or file_label)

                records.append(record)

                for key in record.keys():
                    if key != 'rows':
                        column_names.add(key)

        preferred_order = [
            'collection',
            'collection_country',
            'collection_year',
            'file_label',
            'file_name',
            'collection_file_count',
            'collection_path',
            'size_human',
            'size_mb',
            'size_bytes',
            'preview_line_count',
            'modified_time',
            'encoding',
            'newlines',
            'format_label',
            'delimiter_name',
            'delimiter',
            'sniff_source',
            'columns_first_line',
            'row_count',
            'error',
            'path_rel',
            'full_path',
        ]

        ordered_columns = []
        for col in preferred_order:
            if col in column_names and col not in ordered_columns:
                ordered_columns.append(col)

        for col in sorted(column_names):
            if col not in ordered_columns:
                ordered_columns.append(col)

        payload = {
            'columns': ordered_columns,
            'records': records,
        }

        return app.response_class(
            json.dumps(payload, ensure_ascii=False, allow_nan=False),
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': f'Failed to load swdb preview JSON: {e}'}), 500


@app.route('/api/http_archive/merged_technologies_by_domain')
def get_http_archive_merged_technologies_by_domain():
    try:
        path = HTTP_ARCHIVE_MERGED_TECH_BY_DOMAIN_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404

        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)

        def parse_list(val):
            if val is None or (isinstance(val, float) and math.isnan(val)):
                return []
            if isinstance(val, list):
                return [str(x).strip() for x in val if str(x).strip()]
            s = str(val).strip()
            if s.startswith('[') and s.endswith(']'):
                try:
                    parsed = ast.literal_eval(s)
                    if isinstance(parsed, list):
                        return [str(x).strip() for x in parsed if str(x).strip()]
                except Exception:
                    pass
            parts = re.split(r'[;,]', s)
            return [p.strip() for p in parts if p.strip()]

        def uniq_preserve(seq):
            seen = set()
            out = []
            for item in seq:
                if item not in seen:
                    seen.add(item)
                    out.append(item)
            return out

        records = []
        hacked_domains = 0
        http_counts = []
        swdb_counts = []
        overlap_counts = []

        for rec in df.to_dict('records'):
            site = rec.get('site_url') or rec.get('domain_name')
            http_list = uniq_preserve(parse_list(rec.get('http_arch_technologies')))
            swdb_list = uniq_preserve(parse_list(rec.get('swdb_2022_technologies')))
            http_set = set(http_list)
            swdb_set = set(swdb_list)
            overlap = sorted(http_set & swdb_set)
            only_http = sorted(http_set - swdb_set)
            only_swdb = sorted(swdb_set - http_set)
            hacked_val = str(rec.get('Hacked') or '').strip().lower()
            hacked = hacked_val in {'1', 'true', 'yes', 'y', 't'}
            if hacked:
                hacked_domains += 1
            http_counts.append(len(http_list))
            swdb_counts.append(len(swdb_list))
            overlap_counts.append(len(overlap))
            records.append({
                'site_url': site,
                'hacked': hacked,
                'http_technologies': sorted(http_list),
                'swdb_technologies': sorted(swdb_list),
                'overlap': overlap,
                'only_http': only_http,
                'only_swdb': only_swdb,
                'http_count': len(http_list),
                'swdb_count': len(swdb_list),
                'overlap_count': len(overlap),
                'http_only_count': len(only_http),
                'swdb_only_count': len(only_swdb),
            })

        def avg(vals):
            vals = [v for v in vals if v is not None]
            return float(sum(vals)) / len(vals) if vals else None

        stats = {
            'domains': len(records),
            'hacked_domains': hacked_domains,
            'avg_http_tech': avg(http_counts),
            'avg_swdb_tech': avg(swdb_counts),
            'avg_overlap': avg(overlap_counts),
        }

        payload = {'data': records, 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load merged technologies by domain: {e}'}), 500


# API for temple_db.csv (historical incidents)
@app.route('/api/temple')
def get_temple_data():
    try:
        path = os.path.join(app.root_path, 'data', 'temple_db.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        # Drop completely empty columns (all NaN)
        df = df.drop(columns=[c for c in df.columns if df[c].isna().all()])
        # Normalize column names (strip whitespace)
        df.columns = [c.strip() for c in df.columns]
        df = df.replace({'': None}).replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load temple_db CSV: {e}'}), 500

# Page for temple DB incidents
@app.route('/temple')
def temple_page():
    return render_template('temple.html')

# API + page for ransomware live data (file currently named ranomware_live.csv)
@app.route('/api/ransomware_live')
def get_ransomware_live():
    try:
        path = _ransomware_live_path()
        if not path:
            return jsonify({'error': 'ransomware_live CSV not found (looked for ransomware_live.csv / ranomware_live.csv)'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip() for c in df.columns]
        # Replace empty strings with NaN then with None
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load ransomware_live CSV: {e}'}), 500

@app.route('/ransomware_live')
def ransomware_live_page():
    return render_template('ransomware_live.html')

# API + page for ransom_grained_db.csv (reduced column set for usability)
@app.route('/api/ransom_grained')
def get_ransom_grained():
    try:
        path = os.path.join(app.root_path, 'data', 'ransom_grained_db.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip() for c in df.columns]
        # Rename dots to underscores for JSON field safety in Tabulator
        rename_map = {c: c.replace('.', '_') for c in df.columns}
        df = df.rename(columns=rename_map)
        df = df.where(pd.notnull(df), None)

        # Convert to list of dicts and deep-clean NaN/Inf for strict JSON
        records = df.to_dict('records')
        def clean_value(val):
            if isinstance(val, float):
                if math.isnan(val) or math.isinf(val):
                    return None
            return val
        for rec in records:
            for k, v in list(rec.items()):
                rec[k] = clean_value(v)
        payload = {'columns': list(df.columns), 'data': records}
        try:
            # Ensure no NaN slips through (will raise if present)
            dumped = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        except ValueError:
            # Fallback: second pass (should be unnecessary)
            for rec in records:
                for k, v in list(rec.items()):
                    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                        rec[k] = None
            dumped = json.dumps({'columns': list(df.columns), 'data': records}, ensure_ascii=False, allow_nan=False)
        return app.response_class(dumped, mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load ransom_grained_db CSV: {e}'}), 500

@app.route('/api/ransomware_live/last_updated')
def ransomware_live_last_updated():
    path = _ransomware_live_path()
    if not path or not os.path.exists(path):
        return jsonify({'error': 'ransomware_live CSV not found'}), 404
    updated_at = _file_mtime_iso(path)
    size = None
    try:
        size = os.path.getsize(path)
    except Exception:
        pass
    return jsonify({
        'path': os.path.relpath(path, app.root_path),
        'updated_at': updated_at,
        'size_bytes': size,
    })


@app.route('/api/ransomware_live/refresh', methods=['POST'])
def refresh_ransomware_live():
    dest_path = os.path.join(app.root_path, 'data', 'ranomware_live.csv')
    cmd = ['curl', '-L', RANSOMWARE_LIVE_URL, '-o', dest_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        return jsonify({'error': f'Failed to execute curl: {e}'}), 500

    if result.returncode != 0:
        stderr = (result.stderr or '').strip()
        return jsonify({'error': f'curl failed with code {result.returncode}', 'stderr': stderr}), 500

    if not os.path.exists(dest_path):
        return jsonify({'error': 'Download reported success but file is missing'}), 500

    updated_at = _file_mtime_iso(dest_path)
    size = None
    try:
        size = os.path.getsize(dest_path)
    except Exception:
        pass

    return jsonify({
        'status': 'ok',
        'path': os.path.relpath(dest_path, app.root_path),
        'updated_at': updated_at,
        'size_bytes': size,
    })

@app.route('/ransom_grained')
def ransom_grained_page():
    return render_template('ransom_grained.html')

# ================= Google Spiceworks Data =================
# API endpoint for google_account.csv
@app.route('/api/google_accounts')
def get_google_accounts():
    try:
        path = os.path.join(app.root_path, 'data', 'google_spicework', 'google_account.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load google_account CSV: {e}'}), 500

# API endpoint for google_sites.csv
@app.route('/api/google_sites')
def get_google_sites():
    try:
        path = os.path.join(app.root_path, 'data', 'google_spicework', 'google_sites.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load google_sites CSV: {e}'}), 500

# API endpoint for google_technologies.csv
@app.route('/api/google_technologies')
def get_google_technologies():
    try:
        path = os.path.join(app.root_path, 'data', 'google_spicework', 'google_technologies.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load google_technologies CSV: {e}'}), 500

# Pages for Google Spiceworks datasets
@app.route('/google_accounts')
def google_accounts_page():
    return render_template('google_accounts.html')

@app.route('/google_sites')
def google_sites_page():
    return render_template('google_sites.html')

@app.route('/google_technologies')
def google_technologies_page():
    return render_template('google_technologies.html')

# New endpoint to return basic statistics, including number of unique account_ids
@app.route('/api/stats')
def get_stats():
    """Return basic dataset statistics."""
    try:
        df = pd.read_csv(CSV_PATH)
        stats = {
            'total_records': int(len(df)),
            'unique_urls': int(df['url'].nunique()) if 'url' in df.columns else None,
            'unique_account_ids': int(df['ACCOUNT_ID'].nunique()) if 'ACCOUNT_ID' in df.columns else None,
        }

        # Compute unique site_ids from the secondary CSV if available
        secondary_csv = 'data/ransomed_domains_in_swdb.csv'
        unique_site_ids = None
        if os.path.exists(secondary_csv):
            try:
                df_sites = pd.read_csv(secondary_csv)
                if 'site_ids' in df_sites.columns:
                    all_ids = set()
                    for val in df_sites['site_ids'].dropna().astype(str):
                        for s in str(val).split(';'):
                            sid = s.strip()
                            if sid:
                                all_ids.add(sid)
                    unique_site_ids = int(len(all_ids))
            except Exception:
                # leave unique_site_ids as None if parsing fails
                pass
        stats['unique_site_ids'] = unique_site_ids

        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API endpoint for 8-K filings (8k.csv)
@app.route('/api/eightk')
def get_eightk():
    try:
        path = os.path.join(app.root_path, 'data', '8k.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load 8k CSV: {e}'}), 500

@app.route('/eightk')
def eightk_page():
    return render_template('eightk.html')


# API endpoint for maryland.csv
@app.route('/api/maryland')
def get_maryland():
    try:
        path = os.path.join(app.root_path, 'data', 'maryland.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Drop completely empty columns
        df = df.drop(columns=[c for c in df.columns if df[c].isna().all()])
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load maryland CSV: {e}'}), 500

@app.route('/maryland')
def maryland_page():
    return render_template('maryland.html')

# API endpoint for veris.csv (VERIS incidents dataset)
@app.route('/api/veris')
def get_veris():
    try:
        path = os.path.join(app.root_path, 'data', 'veris.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        selected_cols = [
            'victim_victim_id', 'victim_industry', 'victim_country', 'victim_state',
            'victim_employee_count', 'victim_region', 'victim_revenue_amount',
            'security_incident', 'targeted', 'summary', 'confidence',
            'timeline_incident_year', 'timeline_incident_month', 'timeline_incident_day',
            'timeline_compromise_unit', 'timeline_compromise_value',
            'timeline_discovery_unit', 'timeline_discovery_value',
            'action_hacking_variety', 'action_hacking_vector',
            'action_malware_variety', 'action_malware_name', 'action_malware_vector',
            'action_social_variety', 'action_social_vector',
            'action_error_variety',
            'actor_external_variety', 'actor_external_motive', 'actor_external_country',
            'actor_internal_variety', 'actor_internal_motive',
            'asset_assets', 'asset_cloud',
            'attribute_confidentiality_data_disclosure', 'attribute_confidentiality_data_total',
            'attribute_availability_variety',
            'attribute_integrity_variety',
            'impact_overall_rating', 'impact_overall_amount', 'impact_iso_currency_code',
            'discovery_method_internal_variety', 'discovery_method_external_variety',
            'reference', 'incident_id', 'plus_dbir_year',
        ]
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        available = [c for c in selected_cols if c in df.columns]
        df = df[available]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load veris CSV: {e}'}), 500

@app.route('/veris')
def veris_page():
    return render_template('veris.html')

# API endpoint for eurepoc_data.csv (EuRepoC cyber incidents)
@app.route('/api/eurepoc')
def get_eurepoc():
    try:
        path = os.path.join(app.root_path, 'data', 'eurepoc_data.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Drop completely empty columns
        df = df.drop(columns=[c for c in df.columns if df[c].isna().all()])
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load eurepoc CSV: {e}'}), 500

@app.route('/eurepoc')
def eurepoc_page():
    return render_template('eurepoc.html')

# API endpoint for master_records (10-K compiled dataset)
@app.route('/api/master_records')
def get_master_records():
    try:
        path = os.path.join(app.root_path, 'data', '10k', 'master_records.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        # Normalize column names (strip BOM/whitespace)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load master_records CSV: {e}'}), 500

@app.route('/master_records')
def master_records_page():
    return render_template('master_records.html')

# API endpoint for all_data (10-K full binary feature matrix)
@app.route('/api/all_data')
def get_all_data():
    try:
        path = os.path.join(app.root_path, 'data', '10k', 'all_data.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        # Use low_memory=False due to many columns
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        # Clean NaN again defensively
        for r in records:
            for k,v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load all_data CSV: {e}'}), 500

@app.route('/all_data')
def all_data_page():
    return render_template('all_data.html')

# API endpoint for all_databases.csv (combined overview across datasets)
@app.route('/api/all_databases')
def get_all_databases():
    try:
        path = os.path.join(app.root_path, 'data', 'all_databases.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Normalize empties
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        return app.response_class(json.dumps(records, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load all_databases CSV: {e}'}), 500

@app.route('/all_databases')
def all_databases_page():
    return render_template('all_databases.html')


# ================= Detailed Databases (6-table drill-down) =================
def _load_csv_safe(path, selected_cols=None, rename_dots=False):
    """Load a CSV, clean NaN/Inf, optionally select columns & rename dots."""
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip().strip('\ufeff') for c in df.columns]
    # Drop completely empty columns
    df = df.drop(columns=[c for c in df.columns if df[c].isna().all()], errors='ignore')
    if selected_cols:
        available = [c for c in selected_cols if c in df.columns]
        df = df[available]
    if rename_dots:
        df.columns = [c.replace('.', '_').replace('-', '_') for c in df.columns]
    df = df.replace({'': None})
    df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
    records = df.to_dict('records')
    for r in records:
        for k, v in list(r.items()):
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                r[k] = None
    return records


@app.route('/api/detailed_databases')
def get_detailed_databases():
    """Return all 6 ransomware databases with selected columns for the detailed overview page."""
    try:
        result = {}

        # 1. Temple DB
        temple_path = os.path.join(app.root_path, 'data', 'temple_db.csv')
        result['temple'] = _load_csv_safe(temple_path, selected_cols=[
            'id', 'date_began', 'year', 'org_name', 'location',
            'primary_ci_sector', 'secondary_ci_sector', 'strain_group',
            'mitre_attack_id', 'duration', 'duration_rank',
            'ransom_amount', 'local_currency', 'ransom_scale',
            'paid_status', 'pay_method', 'amount_paid', 'source', 'comments'
        ]) or []

        # 2. Ransomware Live
        rl_path = _ransomware_live_path()
        result['ransomware_live'] = _load_csv_safe(rl_path, selected_cols=[
            'post_title', 'group_name', 'discovered', 'description',
            'published', 'post_url', 'country', 'activity', 'website'
        ]) if rl_path else []

        # 3. Grained DB (select key columns from 100+)
        grained_path = os.path.join(app.root_path, 'data', 'ransom_grained_db.csv')
        result['grained'] = _load_csv_safe(grained_path, selected_cols=[
            'victim', 'sector', 'attacker', 'incident-date',
            'sources', 'payment-outcome',
            'data-destruction', 'data-exfiltration', 'data-exposure', 'data-sale',
            'attack-vector.ransomware-variant',
            'attacker-action.ransom-amount-usd',
            'impact.loss-amount-usd',
            'impact.category.Operational Impact',
            'impact.category.Financial Loss',
        ], rename_dots=True) or []

        # 4. Maryland
        maryland_path = os.path.join(app.root_path, 'data', 'maryland.csv')
        result['maryland'] = _load_csv_safe(maryland_path, selected_cols=[
            'event_date', 'reported_date', 'year', 'month',
            'actor', 'actor_type', 'organization', 'industry',
            'motive', 'event_type', 'event_subtype',
            'magnitude', 'duration', 'description', 'source_url',
            'country', 'state', 'county'
        ]) or []

        # 5. 10-K Master Records
        tenk_path = os.path.join(app.root_path, 'data', '10k', 'master_records.csv')
        result['tenk'] = _load_csv_safe(tenk_path) or []

        # 6. 8-K Filings
        eightk_path = os.path.join(app.root_path, 'data', '8k.csv')
        result['eightk'] = _load_csv_safe(eightk_path) or []

        # 7. VERIS
        veris_path = os.path.join(app.root_path, 'data', 'veris.csv')
        result['veris'] = _load_csv_safe(veris_path, selected_cols=[
            'victim_victim_id', 'victim_industry', 'victim_country',
            'victim_state', 'victim_employee_count',
            'security_incident', 'summary',
            'timeline_incident_year', 'timeline_incident_month',
            'action_malware_variety', 'action_malware_name',
            'action_hacking_variety', 'action_social_variety',
            'actor_external_variety', 'actor_external_motive',
            'attribute_confidentiality_data_disclosure',
            'impact_overall_rating', 'reference',
        ]) or []

        # Include row counts for display
        result['_meta'] = {
            'temple_total': len(result['temple']),
            'ransomware_live_total': len(result['ransomware_live']),
            'grained_total': len(result['grained']),
            'maryland_total': len(result['maryland']),
            'tenk_total': len(result['tenk']),
            'eightk_total': len(result['eightk']),
            'veris_total': len(result['veris']),
        }

        return app.response_class(
            json.dumps(result, allow_nan=False),
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({'error': f'Failed to load detailed databases: {e}'}), 500


@app.route('/detailed_databases')
def detailed_databases_page():
    return render_template('detailed_databases.html')


# API endpoint for final_raw_merged.csv (merged datasets presence matrix)
@app.route('/api/final_raw_merged')
def get_final_raw_merged():
    try:
        path = os.path.join(app.root_path, 'data', 'final_raw_merged.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Normalize empties to None
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        # Compute per-column counts of non-empty values
        col_counts = {}
        for col in df.columns:
            series = df[col]
            count = int(series.map(lambda x: (str(x).strip() if x is not None and not (isinstance(x, float) and math.isnan(x)) else '') != '').sum())
            col_counts[col] = count
        payload = { 'data': records, 'columns': list(df.columns), 'column_counts': col_counts, 'total_rows': len(records) }
        return app.response_class(json.dumps(payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load final_raw_merged CSV: {e}'}), 500

@app.route('/final_raw_merged')
def final_raw_merged_page():
    return render_template('final_raw_merged.html')

# API endpoint for company_presence_matrix.csv
@app.route('/api/company_presence_matrix')
def get_company_presence_matrix():
    try:
        path = os.path.join(app.root_path, 'data', 'company_presence_matrix.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        col_counts = {}
        for col in df.columns:
            series = df[col]
            count = int(series.map(lambda x: (str(x).strip() if x is not None and not (isinstance(x, float) and math.isnan(x)) else '') != '').sum())
            col_counts[col] = count
        payload = { 'data': records, 'columns': list(df.columns), 'column_counts': col_counts, 'total_rows': len(records) }
        return app.response_class(json.dumps(payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load company_presence_matrix CSV: {e}'}), 500

@app.route('/company_presence_matrix')
def company_presence_matrix_page():
    return render_template('company_presence_matrix.html')



# API endpoint for SWDB regions_by_year.csv
@app.route('/api/swdb/regions_by_year')
def get_swdb_regions_by_year():
    try:
        path = os.path.join(app.root_path, 'data', 'swdb', 'regions_by_year.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        col_counts = {}
        for col in df.columns:
            series = df[col]
            count = int(series.map(lambda x: (str(x).strip() if x is not None and not (isinstance(x, float) and math.isnan(x)) else '') != '').sum())
            col_counts[col] = count
        payload = { 'data': records, 'columns': list(df.columns), 'column_counts': col_counts, 'total_rows': len(records) }
        return app.response_class(json.dumps(payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load swdb regions_by_year CSV: {e}'}), 500

@app.route('/swdb/regions_by_year')
def swdb_regions_by_year_page():
    return render_template('swdb_regions_by_year.html')



# ================= HTTP Archive Technologies =================
@app.route('/api/http_archive/muni_tech_raw')
def get_http_archive_muni_tech_raw():
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_RAW_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)
        stats = {
            'total_rows': len(records),
            'unique_domains': len({r.get('domain_name') for r in records if r.get('domain_name')}),
            'unique_matchids': len({r.get('Matchid') for r in records if r.get('Matchid') is not None}),
        }
        payload = {'data': records, 'columns': list(df.columns), 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load muni tech raw CSV: {e}'}), 500


@app.route('/api/http_archive/muni_tech_reduced')
def get_http_archive_muni_tech_reduced():
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)
        stats = {
            'total_rows': len(records),
            'unique_domains': len({r.get('domain_name') for r in records if r.get('domain_name')}),
            'unique_matchids': len({r.get('Matchid') for r in records if r.get('Matchid') is not None}),
        }
        payload = {'data': records, 'columns': list(df.columns), 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load muni tech reduced CSV: {e}'}), 500


@app.route('/api/http_archive/muni_tech_installs')
def get_http_archive_muni_tech_installs():
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404

        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        df['crawl_dt'] = pd.to_datetime(df.get('crawl_date'), errors='coerce') if 'crawl_date' in df.columns else pd.NaT

        def is_hacked(val):
            s = str(val).strip().lower()
            return s in {'1', 'true', 'yes', 'y', 't'}

        def split_values(raw):
            if raw is None:
                return []
            return [p.strip() for p in re.split(r'[;,|]', str(raw)) if p.strip()]

        aggregates = {}
        all_domains = set()
        all_links = set()
        hacked_domains_global = set()

        for rec in df.to_dict('records'):
            tech = rec.get('technology')
            if tech is None or str(tech).strip() == '':
                continue
            tech_key = str(tech).strip()
            agg = aggregates.setdefault(tech_key, {
                'technology': tech_key,
                'categories_set': set(),
                'versions_set': set(),
                'domains': set(),
                'links': set(),
                'matchids': set(),
                'hacked_domains': set(),
                'installs': 0,
                'first_seen': None,
                'last_seen': None,
            })

            agg['categories_set'].update(split_values(rec.get('categories')))
            agg['versions_set'].update(split_values(rec.get('versions')))

            domain = rec.get('domain_name')
            if domain:
                agg['domains'].add(domain)
                all_domains.add(domain)
                if is_hacked(rec.get('hacked')):
                    agg['hacked_domains'].add(domain)
                    hacked_domains_global.add(domain)

            link = rec.get('Link')
            if link:
                agg['links'].add(link)
                all_links.add(link)

            matchid = rec.get('Matchid')
            if matchid not in (None, ''):
                agg['matchids'].add(matchid)

            agg['installs'] += 1

            crawl_dt = rec.get('crawl_dt') if isinstance(rec, dict) else None
            if crawl_dt is None:
                crawl_dt = None
            if crawl_dt is not None and isinstance(crawl_dt, str):
                crawl_dt = pd.to_datetime(crawl_dt, errors='coerce')
            if pd.notna(crawl_dt):
                if agg['first_seen'] is None or crawl_dt < agg['first_seen']:
                    agg['first_seen'] = crawl_dt
                if agg['last_seen'] is None or crawl_dt > agg['last_seen']:
                    agg['last_seen'] = crawl_dt

        records = []
        for val in aggregates.values():
            records.append({
                'technology': val['technology'],
                'categories': '; '.join(sorted(val['categories_set'])) if val['categories_set'] else None,
                'versions': '; '.join(sorted(val['versions_set'])) if val['versions_set'] else None,
                'install_rows': val['installs'],
                'unique_domains': len(val['domains']),
                'hacked_domains': len(val['hacked_domains']),
                'non_hacked_domains': len(val['domains']) - len(val['hacked_domains']),
                'unique_links': len(val['links']),
                'unique_matchids': len(val['matchids']),
                'first_seen': val['first_seen'],
                'last_seen': val['last_seen'],
            })

        records.sort(key=lambda r: (r.get('install_rows') or 0), reverse=True)

        stats = {
            'total_rows': len(df),
            'technologies': len(records),
            'total_installs': sum(r.get('install_rows') or 0 for r in records),
            'unique_domains': len(all_domains),
            'hacked_domains': len(hacked_domains_global),
            'unique_links': len(all_links),
        }

        payload = {'data': records, 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to build muni tech installs: {e}'}), 500


@app.route('/api/http_archive/muni_tech_jaccard_similarity_attack')
def get_http_archive_muni_tech_jaccard_similarity_attack():
    try:
        path = HTTP_ARCHIVE_MUNI_JACCARD_ATTACK_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        list_cols = [
            '1_m_before', '2_m_before', '3_m_before', '4_m_before', 'attack_month_tech',
            '1_m_after_tech', '2_m_after_tech', '3_m_after_tech', '4_m_after_tech',
            '1_m_before_tech_dropped', '1_m_before_tech_added', '2_m_before_tech_dropped', '2_m_before_tech_added',
            '3_m_before_tech_dropped', '3_m_before_tech_added', '4_m_before_tech_dropped', '4_m_before_tech_added',
            '1_m_after_tech_dropped', '1_m_after_tech_added', '2_m_after_tech_dropped', '2_m_after_tech_added',
            '3_m_after_tech_dropped', '3_m_after_tech_added', '4_m_after_tech_dropped'
        ]
        jaccard_cols = [
            'jaccard_attack_4m_before', 'jaccard_attack_3m_before', 'jaccard_attack_2m_before', 'jaccard_attack_1m_before',
            'jaccard_attack_1m_after', 'jaccard_attack_2m_after', 'jaccard_attack_3m_after', 'jaccard_attack_4m_after', 'average_jaccard_before_attack','average_jaccard_after_attack'
        ]

        def parse_list_like(val):
            if val is None:
                return None
            if isinstance(val, str) and val.strip().startswith('[') and val.strip().endswith(']'):
                try:
                    parsed = ast.literal_eval(val)
                    if isinstance(parsed, list):
                        return '; '.join(str(x) for x in parsed)
                except Exception:
                    return val
            return val

        for col in list_cols:
            if col in df.columns:
                df[col] = df[col].apply(parse_list_like)

        for col in jaccard_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)

        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)

        hacked_vals = [str(r.get('Hacked') or '').strip().lower() for r in records]
        hacked_count = sum(1 for v in hacked_vals if v in {'1', 'true', 'yes', 'y', 't'})
        stats = {
            'total_rows': len(records),
            'unique_links': len({r.get('Link') for r in records if r.get('Link')}),
            'hacked_rows': hacked_count,
        }

        payload = {'data': records, 'columns': list(df.columns), 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load muni tech Jaccard CSV: {e}'}), 500


@app.route('/api/http_archive/muni_tech_added_dropped')
def get_http_archive_muni_tech_added_dropped():
    try:
        path = HTTP_ARCHIVE_MUNI_ADDED_DROPPED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404

        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})

        numeric_cols = [
            'n_times_added_before_attack',
            'n_times_dropped_before_attack',
            'n_times_added_after_attack',
            'n_times_dropped_after_attack',
        ]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)

        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)

        def safe_sum(col):
            if col not in df.columns:
                return None
            series = pd.to_numeric(df[col], errors='coerce')
            finite = series[np.isfinite(series)]
            return int(finite.sum()) if not finite.isna().all() else None

        stats = {
            'row_count': len(records),
            'unique_technologies': len({r.get('technology') for r in records if r.get('technology')}),
            'total_added_before': safe_sum('n_times_added_before_attack'),
            'total_dropped_before': safe_sum('n_times_dropped_before_attack'),
            'total_added_after': safe_sum('n_times_added_after_attack'),
            'total_dropped_after': safe_sum('n_times_dropped_after_attack'),
        }

        payload = {'data': records, 'columns': list(df.columns), 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load muni tech added/dropped CSV: {e}'}), 500


@app.route('/api/http_archive/muni_tech_added_dropped_3rd_month')
def get_http_archive_muni_tech_added_dropped_3rd_month():
    try:
        path = HTTP_ARCHIVE_MUNI_ADDED_DROPPED_3RD_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404

        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})

        numeric_cols = [
            'n_times_added_before_attack',
            'n_times_dropped_before_attack',
            'n_times_added_after_attack',
            'n_times_dropped_after_attack',
        ]
        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)

        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)

        def safe_sum(col):
            if col not in df.columns:
                return None
            series = pd.to_numeric(df[col], errors='coerce')
            finite = series[np.isfinite(series)]
            return int(finite.sum()) if not finite.isna().all() else None

        stats = {
            'row_count': len(records),
            'unique_technologies': len({r.get('technology') for r in records if r.get('technology')}),
            'total_added_before': safe_sum('n_times_added_before_attack'),
            'total_dropped_before': safe_sum('n_times_dropped_before_attack'),
            'total_added_after': safe_sum('n_times_added_after_attack'),
            'total_dropped_after': safe_sum('n_times_dropped_after_attack'),
        }

        payload = {'data': records, 'columns': list(df.columns), 'stats': stats}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load muni tech added/dropped 3rd-month CSV: {e}'}), 500


@app.route('/api/http_archive/muni_tech_reduced/pivot')
def pivot_http_archive_muni_tech_reduced():
    mode = request.args.get('mode', 'tech').strip().lower()
    valid_modes = {'tech', 'cat', 'tech_ver'}
    if mode not in valid_modes:
        return jsonify({'error': f"Invalid mode '{mode}'. Choose one of {sorted(valid_modes)}"}), 400
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        df = df.dropna(subset=['Link'])

        def target_series(frame):
            if mode == 'tech':
                return frame['technology']
            if mode == 'cat':
                return frame['categories']
            tech = frame.get('technology')
            ver = frame.get('versions')
            if tech is None:
                return pd.Series([None] * len(frame))
            return tech.fillna('').astype(str) + '|' + (frame.get('versions').fillna('').astype(str) if 'versions' in frame.columns else '')

        values = target_series(df)
        mask = values.notna() & values.astype(str).str.len().gt(0)
        df_filtered = df[mask]
        values_filtered = values[mask]
        if df_filtered.empty:
            return jsonify({'error': 'No data available to pivot for the selected mode'}), 400
        pivot = pd.crosstab(index=df_filtered['Link'], columns=values_filtered)
        pivot = (pivot > 0).astype(int)
        pivot.reset_index(inplace=True)
        pivot = pivot.rename(columns={'Link': 'website'})
        csv_data = pivot.to_csv(index=False)
        return app.response_class(csv_data, mimetype='text/csv')
    except Exception as e:
        return jsonify({'error': f'Failed to build pivot: {e}'}), 500


@app.route('/api/http_archive/muni_tech_reduced/domain/<path:domain>')
def get_http_archive_muni_tech_reduced_domain(domain):
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        if 'domain_name' not in df.columns:
            return jsonify({'error': 'domain_name column missing'}), 400
        mask = df['domain_name'].astype(str).str.lower() == str(domain).lower()
        subset = df[mask]
        if subset.empty:
            return jsonify({'error': f'No records found for {domain}'}), 404
        # Clean NaN/Inf
        records = []
        for rec in subset.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)
        years = sorted({str(rec.get('crawl_date'))[:4] for rec in records if rec.get('crawl_date')}, reverse=True)
        months = sorted({str(rec.get('crawl_date'))[:7] for rec in records if rec.get('crawl_date')}, reverse=True)
        payload = {'data': records, 'years': years, 'months': months, 'domain': domain}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load domain timeline: {e}'}), 500


@app.route('/api/http_archive/muni_tech_reduced/match/<path:matchid>')
def get_http_archive_muni_tech_reduced_match(matchid):
    try:
        path = HTTP_ARCHIVE_MUNI_TECH_REDUCED_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        if 'Matchid' not in df.columns:
            return jsonify({'error': 'Matchid column missing'}), 400
        mask = df['Matchid'].astype(str).str.lower() == str(matchid).lower()
        subset = df[mask]
        if subset.empty:
            return jsonify({'error': f'No records found for Matchid {matchid}'}), 404
        records = []
        for rec in subset.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            records.append(rec)
        months = sorted({str(rec.get('crawl_date'))[:7] for rec in records if rec.get('crawl_date')}, reverse=True)
        payload = {'data': records, 'months': months, 'matchid': matchid}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load match timeline: {e}'}), 500


@app.route('/api/http_archive/tech_grouped')
def get_http_archive_tech_grouped():
    try:
        path = HTTP_ARCHIVE_TECH_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            tech_list = _parse_tech_cat_ver(rec.get('tech_cat_ver'))
            rec['tech_count'] = len(tech_list)
            if tech_list:
                preview_tokens = []
                for item in tech_list[:5]:
                    label = item.get('name') or ''
                    if item.get('version'):
                        label = f"{label} ({item['version']})"
                    preview_tokens.append(label.strip())
                extra = max(len(tech_list) - len(preview_tokens), 0)
                preview = ', '.join([p for p in preview_tokens if p])
                if extra:
                    preview = f"{preview} (+{extra} more)" if preview else f"+{extra} more"
                rec['tech_preview'] = preview
            else:
                rec['tech_preview'] = ''
            domain_val = rec.get('domain_name')
            rec['domain_normalized'] = domain_val.lower().strip() if isinstance(domain_val, str) else None
            records.append(rec)
        payload = {
            'data': records,
            'columns': list(df.columns) + ['tech_count', 'tech_preview']
        }
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load HTTP Archive technologies CSV: {e}'}), 500


@app.route('/api/http_archive/tech_grouped_no_root')
def get_http_archive_tech_grouped_no_root():
    try:
        path = HTTP_ARCHIVE_TECH_NO_ROOT_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            tech_list = _parse_tech_cat_ver(rec.get('tech_cat_ver'))
            rec['tech_count'] = len(tech_list)
            if tech_list:
                preview_tokens = []
                for item in tech_list[:5]:
                    label = item.get('name') or ''
                    if item.get('version'):
                        label = f"{label} ({item['version']})"
                    preview_tokens.append(label.strip())
                extra = max(len(tech_list) - len(preview_tokens), 0)
                preview = ', '.join([p for p in preview_tokens if p])
                if extra:
                    preview = f"{preview} (+{extra} more)" if preview else f"+{extra} more"
                rec['tech_preview'] = preview
            else:
                rec['tech_preview'] = ''
            domain_val = rec.get('domain_name')
            rec['domain_normalized'] = domain_val.lower().strip() if isinstance(domain_val, str) else None
            records.append(rec)
        payload = {
            'data': records,
            'columns': list(df.columns) + ['tech_count', 'tech_preview']
        }
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load HTTP Archive technologies (no root) CSV: {e}'}), 500


@app.route('/api/http_archive/tech_grouped_no_root_v2')
def get_http_archive_tech_grouped_no_root_v2():
    try:
        path = HTTP_ARCHIVE_TECH_NO_ROOT_V2_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = []
        for rec in df.to_dict('records'):
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            tech_list = _parse_tech_cat_ver(rec.get('tech_cat_ver'))
            rec['tech_count'] = len(tech_list)
            if tech_list:
                preview_tokens = []
                for item in tech_list[:5]:
                    label = item.get('name') or ''
                    if item.get('version'):
                        label = f"{label} ({item['version']})"
                    preview_tokens.append(label.strip())
                extra = max(len(tech_list) - len(preview_tokens), 0)
                preview = ', '.join([p for p in preview_tokens if p])
                if extra:
                    preview = f"{preview} (+{extra} more)" if preview else f"+{extra} more"
                rec['tech_preview'] = preview
            else:
                rec['tech_preview'] = ''
            domain_val = rec.get('domain_name')
            rec['domain_normalized'] = domain_val.lower().strip() if isinstance(domain_val, str) else None
            records.append(rec)
        payload = {
            'data': records,
            'columns': list(df.columns) + ['tech_count', 'tech_preview']
        }
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load HTTP Archive technologies (no root v2) CSV: {e}'}), 500


@app.route('/api/http_archive/tech_grouped/<path:domain>')
def get_http_archive_tech_for_domain(domain):
    try:
        path = HTTP_ARCHIVE_TECH_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        if 'domain_name' not in df.columns:
            return jsonify({'error': 'domain_name column is missing in dataset'}), 400
        mask = df['domain_name'].astype(str).str.lower() == str(domain).lower()
        subset = df[mask]
        if subset.empty:
            return jsonify({'error': f'No records found for domain {domain}'}), 404
        subset_records = subset.to_dict('records')
        cleaned = []
        for rec in subset_records:
            for k, v in list(rec.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    rec[k] = None
            cleaned.append(rec)
        timeline = []
        for (crawl_date, root_page), group in subset.groupby(['crawl_date', 'root_page'], dropna=False):
            techs = []
            for val in group['tech_cat_ver']:
                techs.extend(_parse_tech_cat_ver(val))
            seen = set()
            unique_techs = []
            for item in techs:
                key = (item.get('name'), item.get('category'), item.get('version'))
                if key in seen:
                    continue
                seen.add(key)
                unique_techs.append(item)
            first = group.iloc[0].to_dict()
            event = {
                'crawl_date': crawl_date if crawl_date is not None else '',
                'root_page': root_page if root_page is not None else '',
                'technologies': unique_techs,
                'tech_count': len(unique_techs),
                'post_title': first.get('post_title'),
                'link': first.get('Link') or first.get('link'),
                'group_name': first.get('group_name'),
                'published': first.get('published'),
                'start_date': first.get('start_date'),
                'end_date': first.get('end_date'),
                'hacked': first.get('hacked'),
                'population': first.get('population'),
                'matchid': first.get('Matchid'),
            }
            timeline.append(event)
        timeline.sort(key=lambda ev: (_safe_datetime(ev.get('crawl_date')) or datetime.max, ev.get('root_page') or ''))
        all_techs = []
        for ev in timeline:
            all_techs.extend(ev.get('technologies') or [])
        seen_overall = set()
        unique_all = []
        for item in all_techs:
            key = (item.get('name'), item.get('category'), item.get('version'))
            if key in seen_overall:
                continue
            seen_overall.add(key)
            unique_all.append(item)
        summary = {
            'domain': subset.iloc[0].get('domain_name'),
            'post_title': subset.iloc[0].get('post_title'),
            'group_name': subset.iloc[0].get('group_name'),
            'link': subset.iloc[0].get('Link') or subset.iloc[0].get('link'),
            'published': subset.iloc[0].get('published'),
            'start_date': subset.iloc[0].get('start_date'),
            'end_date': subset.iloc[0].get('end_date'),
            'hacked': subset.iloc[0].get('hacked'),
            'population': subset.iloc[0].get('population'),
            'total_events': len(timeline),
            'unique_technologies': len(unique_all),
        }
        payload = {
            'summary': summary,
            'timeline': timeline,
        }
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load domain technologies: {e}'}), 500


@app.route('/api/http_archive/tech_grouped_no_root/<path:domain>')
def get_http_archive_tech_no_root_for_domain(domain):
    try:
        path = HTTP_ARCHIVE_TECH_NO_ROOT_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        if 'domain_name' not in df.columns:
            return jsonify({'error': 'domain_name column is missing in dataset'}), 400
        mask = df['domain_name'].astype(str).str.lower() == str(domain).lower()
        subset = df[mask]
        if subset.empty:
            return jsonify({'error': f'No records found for domain {domain}'}), 404
        timeline = []
        all_techs = []
        for _, row in subset.iterrows():
            row_dict = row.to_dict()
            for k, v in list(row_dict.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    row_dict[k] = None
            techs = _parse_tech_cat_ver(row_dict.get('tech_cat_ver'))
            all_techs.extend(techs)
            event = {
                'published': row_dict.get('published'),
                'start_date': row_dict.get('start_date'),
                'end_date': row_dict.get('end_date'),
                'group_name': row_dict.get('group_name'),
                'matchid': row_dict.get('Matchid'),
                'link': row_dict.get('Link') or row_dict.get('link'),
                'hacked': row_dict.get('hacked'),
                'population': row_dict.get('population'),
                'technologies': techs,
                'tech_count': len(techs),
            }
            timeline.append(event)
        timeline.sort(key=lambda ev: (_safe_datetime(ev.get('published')) or _safe_datetime(ev.get('start_date')) or datetime.max))
        seen_overall = set()
        unique_all = []
        for item in all_techs:
            key = (item.get('name'), item.get('category'), item.get('version'))
            if key in seen_overall:
                continue
            seen_overall.add(key)
            unique_all.append(item)
        first = subset.iloc[0]
        summary = {
            'domain': first.get('domain_name'),
            'post_title': first.get('post_title'),
            'group_name': first.get('group_name'),
            'link': first.get('Link') or first.get('link'),
            'published': first.get('published'),
            'start_date': first.get('start_date'),
            'end_date': first.get('end_date'),
            'hacked': first.get('hacked'),
            'population': first.get('population'),
            'total_events': len(timeline),
            'unique_technologies': len(unique_all),
        }
        payload = {'summary': summary, 'timeline': timeline}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load domain technologies (no root): {e}'}), 500


@app.route('/api/http_archive/tech_grouped_no_root_v2/<path:domain>')
def get_http_archive_tech_no_root_v2_for_domain(domain):
    try:
        path = HTTP_ARCHIVE_TECH_NO_ROOT_V2_CSV
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        df = df.replace({'': None})
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        if 'domain_name' not in df.columns:
            return jsonify({'error': 'domain_name column is missing in dataset'}), 400
        mask = df['domain_name'].astype(str).str.lower() == str(domain).lower()
        subset = df[mask]
        if subset.empty:
            return jsonify({'error': f'No records found for domain {domain}'}), 404
        timeline = []
        all_techs = []
        for _, row in subset.iterrows():
            row_dict = row.to_dict()
            for k, v in list(row_dict.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    row_dict[k] = None
            techs = _parse_tech_cat_ver(row_dict.get('tech_cat_ver'))
            all_techs.extend(techs)
            event = {
                'crawl_date': row_dict.get('crawl_date'),
                'published': row_dict.get('published'),
                'start_date': row_dict.get('start_date'),
                'end_date': row_dict.get('end_date'),
                'group_name': row_dict.get('group_name'),
                'matchid': row_dict.get('Matchid'),
                'link': row_dict.get('Link') or row_dict.get('link'),
                'hacked': row_dict.get('hacked'),
                'population': row_dict.get('population'),
                'technologies': techs,
                'tech_count': len(techs),
            }
            timeline.append(event)
        timeline.sort(key=lambda ev: (_safe_datetime(ev.get('crawl_date')) or _safe_datetime(ev.get('published')) or _safe_datetime(ev.get('start_date')) or datetime.max))
        seen_overall = set()
        unique_all = []
        for item in all_techs:
            key = (item.get('name'), item.get('category'), item.get('version'))
            if key in seen_overall:
                continue
            seen_overall.add(key)
            unique_all.append(item)
        first = subset.iloc[0]
        summary = {
            'domain': first.get('domain_name'),
            'post_title': first.get('post_title'),
            'group_name': first.get('group_name'),
            'link': first.get('Link') or first.get('link'),
            'published': first.get('published'),
            'start_date': first.get('start_date'),
            'end_date': first.get('end_date'),
            'crawl_date_first': subset['crawl_date'].iloc[0] if 'crawl_date' in subset.columns else None,
            'crawl_date_last': subset['crawl_date'].iloc[-1] if 'crawl_date' in subset.columns else None,
            'hacked': first.get('hacked'),
            'population': first.get('population'),
            'total_events': len(timeline),
            'unique_technologies': len(unique_all),
        }
        payload = {'summary': summary, 'timeline': timeline}
        clean_payload = _clean_for_json(payload)
        return app.response_class(json.dumps(clean_payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load domain technologies (no root v2): {e}'}), 500


@app.route('/http_archive/technologies')
def http_archive_technologies_page():
    return render_template('http_archive_technologies.html')


@app.route('/http_archive/technologies/<path:domain>')
def http_archive_technologies_timeline_page(domain):
    return render_template('http_archive_timeline.html', domain=domain)


@app.route('/http_archive/technologies_no_root')
def http_archive_technologies_no_root_page():
    return render_template('http_archive_technologies_no_root.html')


@app.route('/http_archive/technologies_no_root/<path:domain>')
def http_archive_technologies_no_root_timeline_page(domain):
    return render_template('http_archive_timeline_no_root.html', domain=domain)


@app.route('/http_archive/technologies_no_root_v2')
def http_archive_technologies_no_root_v2_page():
    return render_template('http_archive_technologies_no_root_v2.html')


@app.route('/http_archive/technologies_no_root_v2/<path:domain>')
def http_archive_technologies_no_root_v2_timeline_page(domain):
    return render_template('http_archive_timeline_no_root_v2.html', domain=domain)


@app.route('/http_archive/muni_tech_raw')
def http_archive_muni_tech_raw_page():
    return render_template('http_archive_muni_tech_raw.html')


@app.route('/http_archive/muni_tech_reduced')
def http_archive_muni_tech_reduced_page():
    return render_template('http_archive_muni_tech_reduced.html')


@app.route('/http_archive/muni_tech_installs')
def http_archive_muni_tech_installs_page():
    return render_template('http_archive_muni_tech_installs.html')


@app.route('/http_archive/merged_technologies_by_domain')
def http_archive_merged_technologies_by_domain_page():
    return render_template('merged_technologies_by_domain.html')


@app.route('/http_archive/muni_tech_jaccard_similarity_attack')
def http_archive_muni_tech_jaccard_similarity_attack_page():
    return render_template('http_archive_muni_tech_jaccard_similarity_attack.html')


@app.route('/http_archive/muni_tech_added_dropped')
def http_archive_muni_tech_added_dropped_page():
    return render_template('http_archive_muni_tech_added_dropped.html')


@app.route('/http_archive/muni_tech_added_dropped_3rd_month')
def http_archive_muni_tech_added_dropped_3rd_month_page():
    return render_template('http_archive_muni_tech_added_dropped_3rd_month.html')


@app.route('/http_archive/muni_tech_reduced_matchpair')
def http_archive_muni_tech_reduced_matchpair_page():
    return render_template('http_archive_muni_tech_reduced_matchpair.html')


@app.route('/http_archive/muni_tech_reduced_matchpair/<path:matchid>')
def http_archive_muni_tech_reduced_matchpair_timeline_page(matchid):
    return render_template('http_archive_muni_tech_reduced_matchpair_timeline.html', matchid=matchid)


@app.route('/http_archive/muni_tech_reduced/<path:domain>')
def http_archive_muni_tech_reduced_timeline_page(domain):
    return render_template('http_archive_muni_tech_reduced_timeline.html', domain=domain)



# ================= Municipalities (Oliver Revised) =================
# API endpoint for municipalities ransomware_live_municipalities_oliver.csv
@app.route('/api/municipalities/muni_revised_oliver')
def get_muni_revised_oliver():
    try:
        path = os.path.join(app.root_path, 'data', 'municipalities', 'ransomware_live_municipalities_oliver.csv')
        if not os.path.exists(path):
            return jsonify({'error': f'File not found: {path}'}), 404
        df = pd.read_csv(path)
        # Normalize column names (strip BOM/whitespace)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Drop columns entirely empty
        df = df.drop(columns=[c for c in df.columns if df[c].isna().all()])
        # Standard empty string -> None
        df = df.replace({'': None})
        # Clean booleans / normalize 'TRUE'/'FALSE' textual (keep original column name)
        gov_col = None
        for c in df.columns:
            if c.lower().startswith('goverment service'):  # matches "Goverment Service?"
                gov_col = c
                # Normalize values to capitalized True/False strings
                df[c] = df[c].apply(lambda v: None if (pd.isna(v) or str(v).strip()=='' ) else ('True' if str(v).strip().upper() in {'TRUE','T','YES','Y','1'} else ('False' if str(v).strip().upper() in {'FALSE','F','NO','N','0'} else str(v))))
                break
        df = df.replace([float('inf'), -float('inf')], pd.NA).where(pd.notnull(df), None)
        records = df.to_dict('records')
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    r[k] = None
        # Compute stats: number of distinct websites, True/False counts
        website_col = 'website' if 'website' in df.columns else None
        websites = set()
        true_count = false_count = 0
        if gov_col:
            for _, row in df.iterrows():
                val = row[gov_col]
                if val == 'True':
                    true_count += 1
                elif val == 'False':
                    false_count += 1
        if website_col:
            for v in df[website_col].dropna():
                sval = str(v).strip()
                if sval:
                    websites.add(sval)
        payload = {
            'data': records,
            'stats': {
                'total_rows': len(records),
                'distinct_websites': len(websites) if website_col else None,
                'government_service_true': true_count if gov_col else None,
                'government_service_false': false_count if gov_col else None,
                'government_service_column': gov_col
            },
            'columns': list(df.columns)
        }
        return app.response_class(json.dumps(payload, allow_nan=False), mimetype='application/json')
    except Exception as e:
        return jsonify({'error': f'Failed to load municipalities CSV: {e}'}), 500




@app.route('/municipalities/muni_revised_oliver')
def muni_revised_oliver_page():
    return render_template('muni_revised_oliver.html')





if __name__ == '__main__':
    app.run(debug=True, port=8888, host='0.0.0.0')