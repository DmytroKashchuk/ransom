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
        # Replace NaN values with None for better JSON serialization
        df = df.where(pd.notnull(df), None)
        # Convert to records format for Tabulator
        data = df.to_dict('records')
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8888)
