# Ransomware Risk Score (for Websites)

We want to build a **single risk score** for each website that says how likely it is to be hit by ransomware.

We start from what’s already happened: we collect a list of sites that were attacked in the past (source: [ransomware.live](https://ransomware.live)). For each of those sites, we use **Wappalyzer** to fingerprint the technologies in use—things like CMSs, frameworks, servers, and plugins. Then we look for other websites with **similar technology stacks** and use that similarity to compute a first, simple risk score: the more a site’s tech profile resembles known victims, the higher its score.

Next, we scale up. We take a random sample of **3,041,353** domains from the **Spiceworks** database (year **2022**), covering **USA**, **Canada**, and **APAC**. We fingerprint these sites with Wappalyzer as well and compare their stacks to those of the known victims. This lets us **flag** websites that “look like” past targets and might therefore be more attractive to attackers.

Finally we **monitor future ransomware incidents** to see whether the flagged sites actually get hit. Those observations help us validate the approach and **refine** the scoring over time.

---

## Data
- All URLs/domains: `data/unique_urls.csv`
- Total domains: **3,041,353**
- Source of domains: **Spiceworks** (2022)
- Regions: **USA**, **Canada**, **APAC**
- Tech detection: **Wappalyzer**


## Ransomware.live
- Known victims list: [ransomware.live](https://ransomware.live)

## Maryland Data Base
- Known victims list: [cissm.umd.edu](https://cissm.umd.edu/cyber-events-database)

## 10-K Filings Data
- You can find the dataset used in the paper “How Informative are Cybersecurity Risk Disclosures? Empirical Analysis of Breached Firms“, where you utilized 10-K filings for your analysis
- Dataset: [figshare.com](https://doi.org/10.6084/m9.figshare.28789001)

## The Veris Community Database
- The Veris Community Database: [verisframework.org](https://verisframework.org/vcdb.html)

## The Ransomware Decade: The Creation of a Fine-Grained Dataset and a Longitudinal Study
  - The Ransomware Decade: The Creation of a Fine-Grained Dataset and a Longitudinal Study [USENIX Security Paper](https://www.usenix.org/system/files/usenixsecurity25-sarabi.pdf)  
  - Dataset: [Zenodo Papers Database](https://zenodo.org/records/15571866)


# SEC Filings Cyberincidents
- **Who:** U.S. public companies (FPIs use **6-K/20-F**).
- **Effective:** **Sep 5, 2023**.

**Form 8-K (Item 1.05):** report **material** cyber incidents **within 4 business days** of materiality. Start: **Dec 18, 2023** (most) • **Jun 15, 2024** (SRCs).

**Form 8-K (Item 8.01):** optional for **non-material** or **not-yet-determined** incidents; if later deemed **material**, file **Item 1.05** within 4 business days.

**Form 10-K (Item 106):** include cyber risk/strategy/governance for **FY ending ≥ Dec 15, 2023**.

# HTTP Archive Schema
```sql
-- PAGES (schema sketch)
date DATE,
client STRING,
page STRING,
is_root_page BOOL,
root_page STRING,
rank INT64,
wptid STRING,
payload JSON,            -- page-level WPT blob
summary JSON,            -- summarized page metrics
custom_metrics STRUCT<   -- each field is JSON
  a11y JSON, cms JSON, cookies JSON, css_variables JSON,
  ecommerce JSON, element_count JSON, javascript JSON, markup JSON,
  media JSON, origin_trials JSON, performance JSON, privacy JSON,
  responsive_images JSON, robots_txt JSON, security JSON,
  structured_data JSON, third_parties JSON, well_known JSON,
  wpt_bodies JSON, other JSON
>,
lighthouse JSON,
features ARRAY<STRUCT<feature STRING, id STRING, type STRING>>,
technologies ARRAY<STRUCT<technology STRING, categories ARRAY<STRING>, info ARRAY<STRING>>>,
metadata JSON
```