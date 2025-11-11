from flask import Flask, render_template, jsonify
from markupsafe import Markup
from datetime import datetime
import os, json, math
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

@app.route('/')
def index():
    return render_template('index.html')

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
        # Accept either correct or current typo filename
        candidates = [
            os.path.join(app.root_path, 'data', 'ransomware_live.csv'),
            os.path.join(app.root_path, 'data', 'ranomware_live.csv'),
        ]
        path = next((p for p in candidates if os.path.exists(p)), None)
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
        # Large, wide CSV; use low_memory False
        df = pd.read_csv(path, low_memory=False)
        df.columns = [c.strip().strip('\ufeff') for c in df.columns]
        # Drop columns that are completely empty
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
        return jsonify({'error': f'Failed to load veris CSV: {e}'}), 500

@app.route('/veris')
def veris_page():
    return render_template('veris.html')

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
    app.run(debug=True, port=8888, host='127.0.0.1')