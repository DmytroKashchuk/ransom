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
- Known victims list: [ransomware.live](https://ransomware.live)