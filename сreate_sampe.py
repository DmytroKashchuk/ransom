#!/usr/bin/env python3
from pathlib import Path
import pandas as pd

INPUT_FILES = {
    "ransomware_live.csv": Path("data/ranomware_live.csv"),
    "maryland.csv": Path("data/maryland.csv"),
    "10k/master_records.csv": Path("data/10k/master_records.csv"),
    "veris.csv": Path("data/veris.csv"),
}

OUT_ROOT = Path("data2")
N = 1000
SEED = 42


def read_csv_safely(path: Path) -> pd.DataFrame:
    # Try utf-8 first, then latin-1 (common for messy CSVs)
    try:
        return pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        return pd.read_csv(path, low_memory=False, encoding="latin-1")


def main() -> None:
    for out_rel, in_path in INPUT_FILES.items():
        if not in_path.exists():
            raise FileNotFoundError(f"Missing input file: {in_path}")

        df = read_csv_safely(in_path)

        # Sample up to N rows (if df has < N rows, take all)
        k = min(N, len(df))
        sampled = df.sample(n=k, random_state=SEED) if k > 0 else df

        out_path = OUT_ROOT / out_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)

        sampled.to_csv(out_path, index=False)
        print(f"Wrote {k} rows -> {out_path}")

    print("Done.")


if __name__ == "__main__":
    main()
