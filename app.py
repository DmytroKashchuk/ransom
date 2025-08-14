from flask import Flask, render_template, jsonify
import pandas as pd
import os

app = Flask(__name__)

# Path to the CSV file
CSV_PATH = 'data/ransomed_domains_in_swdb_with_accounts.csv'

@app.route('/')
def index():
    return render_template('index.html')

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

        # Replace NaN values with None for better JSON serialization
        df = df.where(pd.notnull(df), None)
        # Convert to records format for Tabulator
        data = df.to_dict('records')
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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

if __name__ == '__main__':
    app.run(debug=True, port=8888)
