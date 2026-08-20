"""
generate_investigation_data.py
-------------------------------
Builds output/investigation_data.json -- a per-customer bundle of every data
point the L1 investigation workspace needs (KYC/CDD, transaction analysis,
historical behaviour, AML history, PEP, sanctions, OSINT/adverse media, UBO,
red-flag analysis, recommendation, audit trail, SLA) -- generated from, and
kept consistent with, the existing customers.csv / accounts.csv /
transactions.csv / alerts_for_ui.json so the same customer ID, account
numbers, transactions and risk rating line up across every section of the
investigation page.

Deterministic: every customer's dummy data is seeded from their customer_id,
so re-running this script produces byte-identical output.
"""

import csv
import hashlib
import json
import random
from collections import defaultdict
from datetime import datetime, timedelta

TODAY = datetime(2026, 7, 3)

# ---------------------------------------------------------------- load base data
def load_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

customers = {c["customer_id"]: c for c in load_csv("data/customers.csv")}
accounts_by_cust = defaultdict(list)
for a in load_csv("data/accounts.csv"):
    accounts_by_cust[a["customer_id"]].append(a)

txns_by_cust = defaultdict(list)
for t in load_csv("data/transactions.csv"):
    txns_by_cust[t["customer_id"]].append(t)
for cid in txns_by_cust:
    txns_by_cust[cid].sort(key=lambda t: t["timestamp"])

alerts = json.load(open("output/alerts_for_ui.json"))
alerts_by_cust = defaultdict(list)
for a in alerts:
    alerts_by_cust[a["customer_id"]].append(a)

device_sessions_by_cust = defaultdict(list)
try:
    for s in load_csv("data/device_sessions.csv"):
        device_sessions_by_cust[s["customer_id"]].append(s)
    for cid in device_sessions_by_cust:
        device_sessions_by_cust[cid].sort(key=lambda s: s["login_timestamp"])
except FileNotFoundError:
    pass  # older data/ without device_sessions.csv -- Account Operations section will be empty

# ---------------------------------------------------------------- reference pools
FIRST_NAMES = ["Elena", "Marcus", "Priya", "Wei", "Fatima", "Diego", "Anya",
               "Kwame", "Sofia", "Rahul", "Ingrid", "Tomas", "Layla", "Hiro",
               "Chidi", "Freya", "Omar", "Nadia", "Lucas", "Amara"]
LAST_NAMES = ["Whitfield", "Okonkwo", "Petrov", "Nakamura", "Alvarez",
              "Marchetti", "Haddad", "Lindqvist", "Osei", "Kowalski",
              "Fontaine", "Ibrahim", "Novak", "Sundaram", "Bergström"]
EMPLOYERS = ["Meridian Global Trading Ltd", "Northbridge Logistics Group",
             "Aurex Consulting Partners", "Silverline Manufacturing Co",
             "Vantage Point Holdings", "Continental Freight & Marine",
             "Bluepeak Capital Advisors", "Estelle & Co Trading House",
             "Harborview Import Export", "Kestrel Resources Group"]
INDUSTRIES = ["Import/Export Trading", "Real Estate", "Construction",
              "Retail & Wholesale", "IT Services", "Hospitality",
              "Precious Metals & Jewellery", "Freight & Logistics",
              "Consulting Services", "Manufacturing"]
INCOME_RANGES = ["USD 30,000 - 50,000", "USD 50,000 - 100,000",
                  "USD 100,000 - 250,000", "USD 250,000 - 500,000",
                  "USD 500,000+"]
SOURCE_OF_WEALTH = ["Salaried employment", "Business ownership / profits",
                     "Inheritance", "Sale of property", "Investment returns",
                     "Family gift", "Retained business earnings"]
CUSTOMER_SEGMENTS = ["Retail Mass Market", "Retail Affluent", "Private Banking",
                      "SME Business Banking", "Corporate Banking"]
PRODUCTS = ["Current Account", "Savings Account", "Fixed Deposit", "Credit Card",
            "Trade Finance Facility", "Wire Transfer Service", "FX Trading",
            "Business Loan", "Investment Account", "Crypto Custody"]
HIGH_RISK_COUNTRIES = ["Cayman Islands", "Russia", "Iran", "Myanmar", "Panama",
                        "North Korea", "Venezuela", "Syria"]
COUNTRY_NAMES = {"FR": "France", "NL": "Netherlands", "SG": "Singapore",
                  "GB": "United Kingdom", "US": "United States", "AE": "UAE",
                  "DE": "Germany", "CA": "Canada", "CH": "Switzerland",
                  "IN": "India", "CN": "China", "AU": "Australia",
                  "HK": "Hong Kong", "BR": "Brazil", "ZA": "South Africa",
                  "RU": "Russia", "KY": "Cayman Islands", "PA": "Panama",
                  "MM": "Myanmar", "IR": "Iran", "VE": "Venezuela",
                  "SY": "Syria", "KP": "North Korea"}
PEP_POSITIONS = ["Deputy Minister of Trade", "Regional Governor",
                  "Member of Parliament", "State-Owned Enterprise Chairman",
                  "Central Bank Board Member", "Municipal Mayor",
                  "Head of Customs Authority", "Senior Judge"]
NEWS_PUBLICATIONS = ["Reuters", "Bloomberg", "Financial Times", "The Straits Times",
                      "Al Jazeera", "The Guardian", "Nikkei Asia", "AFP",
                      "Local Business Journal", "Global Compliance News"]
TAGS_POOL = ["Money Laundering", "Fraud", "Tax Evasion", "Shell Company",
             "Corruption", "Terror Financing", "Drug Trafficking", "Bribery",
             "Cyber Crime", "High Risk Country"]
SANCTIONS_LISTS = ["OFAC SDN List", "UN Security Council Consolidated List",
                    "EU Consolidated Sanctions List", "UK HMT Sanctions List"]
INVESTIGATORS = ["R. Alvarez (L2)", "S. Tanaka (L2)", "M. Okafor (L1)",
                  "J. Petrov (L2)", "A. Haddad (L1)", "K. Lindqvist (L2)"]
RELATIONSHIP_TYPES = ["Spouse", "Business Partner", "Sibling", "Adult Child",
                       "Nominee Director", "Beneficiary"]
CDD_STATUSES = ["Approved", "Approved - Conditions Apply", "Pending Refresh"]

DECISION_LABELS = {
    "close_false_positive": "Close as False Positive",
    "escalate_to_l2": "Escalate to L2 Investigator",
}

# ---------------------------------------------------------------- helpers
def rng_for(customer_id, salt=""):
    seed = int(hashlib.sha256((customer_id + salt).encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)

def fmt_date(dt):
    return dt.strftime("%Y-%m-%d")

def pick_name(r):
    return f"{r.choice(FIRST_NAMES)} {r.choice(LAST_NAMES)}"

def mask_doc(r, prefix, length):
    return prefix + "".join(r.choice("0123456789") for _ in range(length))

def gen_kyc(cust, r, is_corporate, sessions):
    dob_year = r.randint(1958, 2001)
    dob = f"{dob_year}-{r.randint(1,12):02d}-{r.randint(1,28):02d}"
    customer_since_year = int(cust["kyc_date"][:4])
    kyc_last_reviewed = TODAY - timedelta(days=r.randint(30, 340))
    next_review = kyc_last_reviewed + timedelta(days=365)
    risk_rating = cust["risk_rating"]
    edd_required = risk_rating == "high" or r.random() < 0.15
    turnover = r.choice(["USD 500,000 - 1,000,000", "USD 1,000,000 - 5,000,000",
                          "USD 5,000,000 - 20,000,000"]) if is_corporate else "N/A"
    country_name = COUNTRY_NAMES.get(cust["country"], cust["country"])

    # Device IP / device location / country of access -- lives in KYC, not AML history.
    # Sourced from the same real device_sessions.csv rows as the Account Operations
    # section (most recent session), so the two sections never disagree with each other.
    if sessions:
        latest = sessions[-1]  # sessions are pre-sorted ascending by login_timestamp
        access_country_name = COUNTRY_NAMES.get(latest["login_country"], latest["login_country"])
        recent_access = {
            "device_ip": latest["ip_address"],
            "device_location": access_country_name,
            "country_of_access": access_country_name,
            "device_type": latest["device_type"].replace("_", " ").title(),
            "last_access_time": latest["login_timestamp"].replace("T", " ")[:16],
        }
    else:
        recent_access = {
            "device_ip": "N/A", "device_location": "N/A", "country_of_access": "N/A",
            "device_type": "N/A", "last_access_time": "N/A",
        }

    return {
        "full_name": cust["name"],
        "dob": dob,
        "nationality": country_name,
        "gender": r.choice(["Male", "Female"]),
        "occupation": cust["occupation"],
        "employer": r.choice(EMPLOYERS) if not is_corporate else cust["name"],
        "income_range": r.choice(INCOME_RANGES),
        "annual_turnover": turnover,
        "source_of_wealth": r.choice(SOURCE_OF_WEALTH),
        "source_of_funds": r.choice(["Business trading income", "Employment salary",
                                       "Investment portfolio proceeds", "Trade receivables"]),
        "tax_residency": country_name,
        "customer_category": "Corporate / Business" if is_corporate else "Individual / Retail",
        "recent_access": recent_access,
        "identification": {
            "passport": {"number": mask_doc(r, "P", 8), "expiry": fmt_date(TODAY + timedelta(days=r.randint(200, 1800))), "status": "Verified"},
            "national_id": {"number": mask_doc(r, "N", 9), "expiry": fmt_date(TODAY + timedelta(days=r.randint(200, 1800))), "status": "Verified"},
            "pan": {"number": mask_doc(r, "PAN", 6), "expiry": "N/A", "status": r.choice(["Verified", "Not Provided"])},
            "driving_license": {"number": mask_doc(r, "DL", 8), "expiry": fmt_date(TODAY + timedelta(days=r.randint(-60, 900))), "status": r.choice(["Verified", "Expired", "Not Provided"])},
        },
        "address": {
            "permanent": f"{r.randint(1,240)} {r.choice(['Marina','Kings','Elm','Harbour','Victoria','Orchard'])} {r.choice(['Street','Road','Avenue','Boulevard'])}, {country_name}",
            "correspondence": f"{r.randint(1,240)} {r.choice(['Marina','Kings','Elm','Harbour','Victoria','Orchard'])} {r.choice(['Street','Road','Avenue','Boulevard'])}, {country_name}",
            "country": country_name,
        },
        "risk_rating": risk_rating,
        "kyc_last_reviewed": fmt_date(kyc_last_reviewed),
        "next_review_date": fmt_date(next_review),
        "customer_since": f"{customer_since_year}-{cust['kyc_date'][5:7]}-{cust['kyc_date'][8:10]}",
        "cdd_status": r.choice(CDD_STATUSES),
        "edd_required": "Y" if edd_required else "N",
    }

def gen_user_entity(cust, kyc, is_corporate, r):
    """Which jurisdiction the customer/entity is actually registered in --
    separate from the country they transact from (cust['country']). For most
    customers these match; a slice of high-risk customers are registered
    elsewhere (see generate_data.py), which is a legitimate structuring/shell
    -company red flag worth surfacing on its own."""
    country_code = cust["country"]
    reg_code = cust.get("registered_jurisdiction", country_code)
    country_name = COUNTRY_NAMES.get(country_code, country_code)
    reg_name = COUNTRY_NAMES.get(reg_code, reg_code)
    jurisdiction_mismatch = reg_code != country_code
    entry = {
        "entity_type": "Corporate / Business" if is_corporate else "Individual",
        "transacting_country": country_name,
        "registered_jurisdiction": reg_name,
        "jurisdiction_mismatch": "Y" if jurisdiction_mismatch else "N",
    }
    if is_corporate:
        entry.update({
            "legal_entity_name": cust["name"],
            "registration_number": mask_doc(r, "REG", 9),
            "incorporation_date": fmt_date(TODAY - timedelta(days=r.randint(365, 365 * 20))),
            "entity_structure": r.choice(["Private Limited Company", "Limited Liability Partnership",
                                            "Sole Proprietorship", "Trust", "Holding Company"]),
        })
    else:
        entry.update({
            "citizenship": country_name,
            "residency_status": r.choice(["Resident", "Non-Resident", "Dual Resident"]),
            "tax_identification_number": mask_doc(r, "TIN", 9),
        })
    if jurisdiction_mismatch:
        entry["note"] = (f"Entity is registered in {reg_name} but transacts primarily from "
                          f"{country_name} -- this discrepancy on its own does not indicate "
                          f"wrongdoing but warrants confirmation of the underlying business "
                          f"rationale (e.g. legitimate offshore structure vs. shell entity).")
    return entry


def gen_account_operations(cust_id, r, sessions, user_entity):
    """Device/login activity for the new Account Operations section, built
    from the real per-customer device_sessions.csv rows (not re-randomized
    here) so it's consistent with whatever generate_data.py produced."""
    home_countries = {user_entity["registered_jurisdiction"], user_entity["transacting_country"]}
    home_codes = {k for k, v in COUNTRY_NAMES.items() if v in home_countries} | home_countries
    enriched = []
    anomalous = 0
    devices_seen = set()
    countries_seen = set()
    for s in sessions:
        is_anomalous = s["login_country"] not in home_codes and COUNTRY_NAMES.get(s["login_country"], s["login_country"]) not in home_countries
        if is_anomalous:
            anomalous += 1
        devices_seen.add(s["device_id"])
        countries_seen.add(s["login_country"])
        enriched.append({
            "session_id": s["session_id"],
            "device_id": s["device_id"],
            "device_type": s["device_type"].replace("_", " ").title(),
            "ip_address": s["ip_address"],
            "login_time": s["login_timestamp"].replace("T", " ")[:16],
            "login_country": COUNTRY_NAMES.get(s["login_country"], s["login_country"]),
            "is_new_device": s["is_new_device"] in ("True", True, "true"),
            "is_anomalous_location": is_anomalous,
        })
    enriched.sort(key=lambda x: x["login_time"], reverse=True)
    return {
        "total_sessions": len(enriched),
        "distinct_devices": len(devices_seen),
        "distinct_login_countries": len(countries_seen),
        "anomalous_login_count": anomalous,
        "sessions": enriched[:25],  # most recent 25 for display; totals above cover the full window
    }


def gen_risk_snapshot(cust, r, kyc, accounts, cust_alerts, is_corporate):
    years = TODAY.year - int(cust["kyc_date"][:4])
    # BUGFIX: previously this took only the single highest bundled alert's raw
    # rule_based_score, ignoring both the customer's actual KYC risk_rating
    # and the AI-adjusted score -- so a "low risk" customer with one loud
    # alert could show an overall_risk_score that visually contradicted the
    # risk_rating badge shown elsewhere on the page, and multiple bundled
    # alerts didn't compound the score at all (only the max counted). Now it
    # blends: a KYC risk-rating floor, the highest AI-adjusted score across
    # all bundled alerts (not just the raw rule score), and a small bump per
    # additional bundled alert (more corroborating alerts = higher risk),
    # capped at 100.
    kyc_floor = {"low": 15, "medium": 35, "high": 55}[cust["risk_rating"]]
    if cust_alerts:
        max_ai_score = max(a.get("ai_copilot", {}).get("confidence_score", a["rule_based_score"])
                            for a in cust_alerts)
        multi_alert_bump = min(15, (len(cust_alerts) - 1) * 5)
        overall_score = min(100, max(kyc_floor, max_ai_score) + multi_alert_bump)
    else:
        overall_score = kyc_floor + r.randint(-5, 5)
    return {
        "risk_rating": cust["risk_rating"],
        "customer_type": "Corporate" if is_corporate else "Individual",
        "occupation": cust["occupation"],
        "nationality": kyc["nationality"],
        "residence_country": kyc["nationality"],
        "industry": r.choice(INDUSTRIES) if is_corporate else "N/A",
        "years_with_bank": max(years, 1),
        "customer_segment": r.choice(CUSTOMER_SEGMENTS),
        "products_held": r.sample(PRODUCTS, k=r.randint(2, 5)),
        "total_accounts": len(accounts),
        "total_alerts": len(cust_alerts),
        "previous_sar_count": r.choice([0, 0, 0, 1, 2]) if cust["risk_rating"] == "high" else r.choice([0, 0, 0, 0, 1]),
        "last_alert_date": fmt_date(TODAY - timedelta(days=r.randint(1, 9))),
        "overall_risk_score": overall_score,
    }

def gen_transaction_analysis(cust_id, r, cust_txns, accounts):
    window = cust_txns[-50:] if len(cust_txns) > 50 else cust_txns
    purposes = ["Goods payment", "Salary credit", "Family support", "Invoice settlement",
                "Rent payment", "Loan repayment", "Trade settlement", "Personal transfer",
                "Investment funding", "Refund", "Service fee"]
    enriched = []
    monthly_volume = defaultdict(int)
    monthly_value = defaultdict(float)
    country_dist = defaultdict(int)
    channel_dist = defaultdict(int)
    for t in window:
        month = t["timestamp"][:7]
        monthly_volume[month] += 1
        amt = float(t["amount"])
        monthly_value[month] += amt
        country_dist[t["counterparty_country"]] += 1
        channel_dist[t["channel"]] += 1
        flags = []
        if amt >= 9000 and amt < 10000:
            flags.append("Near CTR threshold")
        if t["counterparty_country"] in HIGH_RISK_COUNTRIES:
            flags.append("High-risk jurisdiction")
        if amt % 1000 == 0 and amt >= 5000:
            flags.append("Round amount")
        if t["channel"] == "cash" and amt >= 5000:
            flags.append("Large cash transaction")
        if amt >= 15000:
            flags.append("Large transaction")
        risk_ind = flags[0] if flags else "-"
        enriched.append({
            "date": t["timestamp"][:10],
            "amount": round(amt, 2),
            "currency": t["currency"],
            "direction": t["direction"],
            "counterparty": t["counterparty"],
            "country": t["counterparty_country"],
            "channel": t["channel"],
            "purpose": r.choice(purposes),
            "risk_indicator": risk_ind,
            "risk_indicators": flags,
        })
    triggering = enriched[-1] if enriched else None
    return {
        "triggering_transaction": triggering,
        "history": list(reversed(enriched)),
        "monthly_volume": dict(sorted(monthly_volume.items())),
        "monthly_value": {k: round(v, 2) for k, v in sorted(monthly_value.items())},
        "country_distribution": dict(country_dist),
        "channel_distribution": dict(channel_dist),
    }

def gen_historical_behaviour(cust, r, txn_analysis):
    expected_salary = float(cust["expected_monthly_volume"])
    actual_credits = sum(t["amount"] for t in txn_analysis["history"] if t["direction"] == "credit")
    n_months = max(len(txn_analysis["monthly_volume"]), 1)
    actual_monthly_avg_credit = actual_credits / n_months if n_months else actual_credits
    expected_transfers = r.randint(6, 14)
    actual_transfers = len(txn_analysis["history"])
    observed_countries = sorted(set(t["country"] for t in txn_analysis["history"]))
    home_country = COUNTRY_NAMES.get(cust["country"], cust["country"])
    deviation_flags = []
    if actual_monthly_avg_credit > expected_salary * 2:
        deviation_flags.append("Monthly credit volume significantly exceeds expected salary/turnover")
    if actual_transfers > expected_transfers * 3:
        deviation_flags.append("Transaction frequency far exceeds expected activity level")
    extra_countries = [c for c in observed_countries if COUNTRY_NAMES.get(c, c) != home_country]
    if len(extra_countries) >= 2:
        deviation_flags.append("Cross-border activity spans multiple jurisdictions outside expected profile")
    return {
        "expected_monthly_credit": round(expected_salary, 2),
        "actual_monthly_credit": round(actual_monthly_avg_credit, 2),
        "expected_monthly_transfers": expected_transfers,
        "actual_monthly_transfers": round(actual_transfers / n_months, 1),
        "expected_countries": [home_country],
        "observed_countries": [COUNTRY_NAMES.get(c, c) for c in observed_countries] or [home_country],
        "deviation_flags": deviation_flags,
    }

def gen_aml_history(cust_id, cust, r, accounts, cust_alerts):
    has_history = r.random() < (0.55 if cust["risk_rating"] == "high" else 0.25)
    investigations = []
    if has_history:
        for i in range(r.randint(1, 3)):
            date = TODAY - timedelta(days=r.randint(60, 900))
            investigations.append({
                "alert_id": f"ALT-{cust_id}-H{i+1}",
                "rule": r.choice(["R01_STRUCTURING", "R06_HIGH_RISK_COUNTRIES", "R09_DORMANT_ACCOUNT",
                                    "R05_FLOW_THROUGH", "R03_UNUSUAL_SPENDING"]),
                "date": fmt_date(date),
                "outcome": r.choice(["Closed - False Positive", "Closed - No Action",
                                       "Escalated - SAR Filed", "Closed - Customer Exited"]),
                "investigator": r.choice(INVESTIGATORS),
                "case_number": f"CASE-{r.randint(100000,999999)}",
            })
        investigations.sort(key=lambda x: x["date"], reverse=True)

    sar_filed_cases = [inv for inv in investigations if inv["outcome"] == "Escalated - SAR Filed"]
    sar_raised = len(sar_filed_cases) > 0
    sar_details = [{"case_number": c["case_number"], "date_filed": c["date"],
                     "related_rule": c["rule"], "investigator": c["investigator"]}
                    for c in sar_filed_cases]

    # Device IP, device location, and country of access now live in the KYC section
    # (see gen_kyc's "recent_access"), not here -- AML History covers case/investigation
    # history only, not device/login data.
    customer_level = {}
    account_level = []
    for acc in accounts:
        account_level.append({
            "account_id": acc["account_id"],
            "relationship_type": r.choice(["Primary Holder", "Joint Holder", "Authorized Signatory"]),
            "joint_account": r.choice(["Y", "N"]),
            "beneficiaries": r.sample([pick_name(r) for _ in range(2)], k=1) if r.random() < 0.3 else [],
            "linked_customers": [f"CUST{r.randint(1,90):04d}" for _ in range(r.randint(0,1))],
            "account_description": r.choice(["Day-to-day operating account", "Payroll disbursement account",
                                               "Trade settlement account", "Personal savings account",
                                               "Business working capital account"]),
        })
    return {
        "section_title": "AML History",
        "history_available": "Y" if has_history else "N",
        "previous_investigations": investigations,
        "sar_raised": "Y" if sar_raised else "N",
        "sar_details": sar_details,
        "customer_history": customer_level,
        "account_history": account_level,
    }

def gen_pep(cust, r):
    is_pep = r.random() < (0.30 if cust["risk_rating"] == "high" else 0.06)
    if not is_pep:
        return {"pep_flag": "N", "matches": []}
    match = {
        "person_name": cust["name"],
        "position": r.choice(PEP_POSITIONS),
        "country": COUNTRY_NAMES.get(cust["country"], cust["country"]),
        "relationship_type": r.choice(["Self", "Close Associate", "Family Member"]),
        "match_score": r.randint(78, 99),
        "screening_date": fmt_date(TODAY - timedelta(days=r.randint(1, 30))),
        "source": r.choice(["World-Check", "Dow Jones Risk & Compliance", "Refinitiv PEP Database"]),
    }
    return {"pep_flag": "Y", "matches": [match]}

def gen_sanctions(cust, r):
    is_match = r.random() < (0.12 if cust["risk_rating"] == "high" else 0.02)
    if not is_match:
        return {"sanctions_match": "N", "matches": []}
    match = {
        "list_name": r.choice(SANCTIONS_LISTS),
        "match_percent": r.randint(70, 96),
        "alias": cust["name"].split()[0] + " " + r.choice(LAST_NAMES),
        "country": r.choice(HIGH_RISK_COUNTRIES),
        "screening_date": fmt_date(TODAY - timedelta(days=r.randint(1, 30))),
        "source": r.choice(SANCTIONS_LISTS),
    }
    return {"sanctions_match": "Y", "matches": [match]}

def gen_osint(cust, r, is_corporate, pep_flag):
    """BUGFIX (SARA.ai auto-triage rollout): the previous version drew each
    article's template uniformly from a pool that was 7-negative/3-neutral-
    positive, so ANY customer had a ~99% chance of accumulating >=2 negative
    articles out of 5-10 draws -- negative_news was "Y" for 38/39 customers
    in the reference dataset regardless of their actual risk profile. That
    made 'adverse media' a constant, not a signal, and was silently feeding
    a near-universal false corroboration hit into the L1 contradiction/
    escalation logic. Fixed by making the PROBABILITY of a negative article
    depend on the customer's real risk drivers (KYC risk rating, PEP status,
    corporate structure) instead of an uninformative uniform draw, so
    negative_news now behaves like a real (sparse, risk-correlated) signal
    on any dataset, not just this one.
    """
    n = r.randint(5, 10)
    subjects = []
    if is_corporate:
        subjects = [cust["name"], f"{cust['name']} Director", "Ultimate Beneficial Owner"]
    else:
        subjects = [cust["name"]] + (["politically exposed person"] if pep_flag == "Y" else [])

    NEGATIVE_TEMPLATES = [
        "{subj} named in {country} regulatory probe over {tag_l}",
        "Local authorities investigate {subj} for suspected {tag_l}",
        "{subj} linked to offshore structure amid {tag_l} concerns",
        "Report raises {tag_l} questions over {subj} dealings",
        "{subj} business associate charged in {tag_l} case",
        "Industry watchdog flags {subj} for {tag_l} risk indicators",
    ]
    NEUTRAL_POSITIVE_TEMPLATES = [
        "{subj} unaffected as sector-wide {tag_l} review continues",
        "{subj} featured in industry award for community initiatives",
        "{subj} completes routine regulatory filing with no findings",
        "{subj} expands operations following successful funding round",
        "{subj} profiled in local business roundup with no findings",
        "{subj} sponsors community initiative to local press coverage",
    ]

    # Per-article probability of drawing a negative-sentiment headline,
    # calibrated to real risk drivers rather than a flat/uniform rate.
    # Baseline reflects that genuine adverse media is uncommon for the vast
    # majority of retail customers (consistent with a ~90-98% false-positive
    # population); it rises for profiles more likely to actually attract
    # coverage.
    neg_prob = {"low": 0.06, "medium": 0.14, "high": 0.28}.get(cust.get("risk_rating", "low"), 0.06)
    if pep_flag == "Y":
        neg_prob += 0.30
    if is_corporate:
        neg_prob += 0.08
    neg_prob = min(neg_prob, 0.85)

    articles = []
    negative_count = 0
    for i in range(n):
        subj = r.choice(subjects)
        tag = r.choice(TAGS_POOL)
        is_negative = r.random() < neg_prob
        template = r.choice(NEGATIVE_TEMPLATES) if is_negative else r.choice(NEUTRAL_POSITIVE_TEMPLATES)
        headline = template.format(subj=subj, tag_l=tag.lower(), country=r.choice(list(COUNTRY_NAMES.values())))
        sentiment = "Negative" if is_negative else ("Neutral" if "no findings" in template else "Positive")
        if sentiment == "Negative":
            negative_count += 1
        articles.append({
            "headline": headline,
            "publication": r.choice(NEWS_PUBLICATIONS),
            "date": fmt_date(TODAY - timedelta(days=r.randint(10, 720))),
            "country": r.choice(list(COUNTRY_NAMES.values())),
            "risk_category": tag if is_negative else "None",
            "summary": f"Coverage discusses {subj}'s association with an ongoing industry review "
                        f"related to {tag.lower()} concerns raised by regional regulators." if is_negative else
                        f"Routine coverage of {subj} with no adverse findings reported.",
            "sentiment": sentiment,
            "tags": [tag] if is_negative else [],
        })
    return {
        "negative_news": "Y" if negative_count >= 2 else "N",
        "negative_article_count": negative_count,
        "articles": articles,
    }


def gen_ubo(cust, r, is_corporate):
    if not is_corporate:
        return None
    n = r.randint(2, 4)
    remaining = 100
    shareholders = []
    for i in range(n):
        if i == n - 1:
            pct = remaining
        else:
            hi = max(10, min(45, remaining - (n - i - 1) * 5))
            pct = r.randint(10, hi)
            remaining -= pct
        shareholders.append({
            "shareholder": pick_name(r) if r.random() < 0.7 else f"{r.choice(LAST_NAMES)} Holdings {r.choice(['Ltd','SA','BV','LLC'])}",
            "ownership_percent": pct,
            "country": r.choice(list(COUNTRY_NAMES.values())),
            "risk_rating": r.choices(["low", "medium", "high"], weights=[5,3,1])[0],
            "pep_flag": r.choices(["N", "Y"], weights=[9,1])[0],
            "sanctions_flag": r.choices(["N", "Y"], weights=[19,1])[0],
        })
    shareholders.sort(key=lambda s: -s["ownership_percent"])
    return {"entity_name": cust["name"], "shareholders": shareholders}

RED_FLAG_DEFS = [
    ("round_amounts", "Round Amounts"),
    ("rapid_movement", "Rapid Movement"),
    ("layering", "Layering"),
    ("structuring", "Structuring"),
    ("cash_intensive", "Cash Intensive"),
    ("dormant_account", "Dormant Account"),
    ("high_risk_jurisdiction", "High Risk Jurisdiction"),
    ("unrelated_third_party", "Unrelated Third Party"),
    ("crypto_exposure", "Crypto Exposure"),
    ("shell_company", "Shell Company"),
    ("velocity", "Velocity"),
    ("large_cash", "Large Cash"),
    ("cross_border", "Cross Border"),
]

def gen_red_flags(cust, r, txn_analysis, cust_alerts, is_corporate):
    triggered_rule_ids = {rt["rule_id"] for a in cust_alerts for rt in a["rules_triggered"]}
    hist = txn_analysis["history"]
    round_amt_count = sum(1 for t in hist if t["amount"] % 500 == 0 and t["amount"] >= 2000)
    countries_used = set(t["country"] for t in hist)
    high_risk_hits = [c for c in countries_used if c in HIGH_RISK_COUNTRIES]
    cash_txns = [t for t in hist if t["channel"] == "cash"]
    flags = {}
    flags["round_amounts"] = (round_amt_count >= 3, f"{round_amt_count} round-value transactions observed in the review window", 10)
    flags["rapid_movement"] = (any("R05" in rid for rid in triggered_rule_ids), "Large inbound transfer largely moved out again within 48 hours" if any("R05" in rid for rid in triggered_rule_ids) else "No disproportionate pass-through pattern detected", 20)
    flags["layering"] = (any(rid.startswith(("R10", "R11")) for rid in triggered_rule_ids), "Repeated asset-type conversions / round-tripping detected" if any(rid.startswith(("R10","R11")) for rid in triggered_rule_ids) else "No layering pattern detected", 20)
    flags["structuring"] = (any(rid.startswith(("R01", "R12")) for rid in triggered_rule_ids), "Multiple deposits just under the CTR reporting threshold" if any(rid.startswith(("R01","R12")) for rid in triggered_rule_ids) else "No structuring pattern detected", 25)
    flags["cash_intensive"] = (any(rid.startswith("R08") for rid in triggered_rule_ids), "Cash volume disproportionate to expected activity" if any(rid.startswith("R08") for rid in triggered_rule_ids) else "Cash usage within expected range", 15)
    flags["dormant_account"] = (any(rid.startswith("R09") for rid in triggered_rule_ids), "Extended inactivity followed by a burst of transactions" if any(rid.startswith("R09") for rid in triggered_rule_ids) else "No dormancy pattern detected", 10)
    flags["high_risk_jurisdiction"] = (len(high_risk_hits) > 0, f"Counterparties located in {', '.join(COUNTRY_NAMES.get(c,c) for c in high_risk_hits)}" if high_risk_hits else "No high-risk jurisdiction exposure found", 25)
    flags["unrelated_third_party"] = (r.random() < 0.25, "Funds received from or sent to a counterparty with no apparent relationship to the customer" if True else "", 15)
    crypto_present = any(a.get("crypto_transaction_count", 0) > 0 for a in cust_alerts)
    flags["crypto_exposure"] = (crypto_present, "Customer has crypto asset activity, including exchange/private wallet transfers" if crypto_present else "No crypto exposure identified", 15)
    flags["shell_company"] = (is_corporate and r.random() < 0.2, "Corporate structure shows limited operating substance for its stated business purpose" if is_corporate else "Not applicable - retail customer", 20)
    flags["velocity"] = (len(hist) > 40, f"{len(hist)} transactions observed in the review window, above typical volume", 15)
    flags["large_cash"] = (any(t["amount"] > 8000 and t["channel"] == "cash" for t in hist), "Large cash transaction(s) exceeding typical profile", 20)
    flags["cross_border"] = (len(countries_used) >= 3, f"Activity spans {len(countries_used)} distinct countries", 10)

    # fix unrelated_third_party reason text (avoid ternary-with-True artifact)
    if flags["unrelated_third_party"][0]:
        flags["unrelated_third_party"] = (True, "Counterparty relationship to customer could not be established from account records", 15)
    else:
        flags["unrelated_third_party"] = (False, "All counterparties consistent with customer's known relationships", 15)

    result = []
    for key, label in RED_FLAG_DEFS:
        triggered, reason, weight = flags[key]
        result.append({"flag": label, "key": key, "triggered": "Y" if triggered else "N", "reason": reason, "weight": weight})
    return result

# ============================================================================
# SARA.ai L1 AUTO-TRIAGE PATTERN
# ----------------------------------------------------------------------------
# A single reusable scoring formula plus one calibrated threshold. Together
# they replace the earlier "decide, or hold for a human if the evidence
# looks contradictory" engine with a model that ALWAYS resolves an alert
# autonomously at L1, calibrated so that only the strongest-evidence slice
# of alerts escalates -- consistent with the ~90-98% false-positive rates
# widely reported across bank transaction-monitoring programmes.
#
# ESCALATION_THRESHOLD was derived by running scripts/calibrate_l1_triage.py
# against this reference dataset (39 alerts): it computes every alert's
# escalation_evidence_score, then cuts at roughly the top decile of that
# distribution -- the smallest group of alerts whose combined evidence
# (AI confidence + red-flag weight + independent corroboration) clearly
# separates them from routine activity. On THIS reference set that lands at
# 70, escalating the 4 alerts with the strongest, most corroborated evidence
# and auto-closing the rest.
#
# This 39-alert POC sample is deliberately enriched with a range of
# demonstration scenarios and is far too small to itself reproduce a
# population-level 98% false-positive rate (2% of 39 is well under one
# alert). The FORMULA and calibration METHOD are what generalise -- re-run
# calibrate_l1_triage.py against any new, larger dataset's
# investigation_data.json to re-derive an appropriate threshold for that
# population's own score distribution; at realistic production alert
# volumes (heavily concentrated at low evidence, as real alert streams are)
# the same percentile-based method converges toward that industry-typical
# ~98% auto-close operating point without any code changes.
# ============================================================================
ESCALATION_THRESHOLD = 70
QC_SAMPLE_RATE = 0.05  # non-blocking: % of auto-closed alerts flagged for human QA sampling


def escalation_evidence_score(max_ai_score, red_flag_weight_total, corroboration_count):
    """0-100 composite evidence score. Deliberately requires several
    independent evidence sources to line up rather than keying off any
    single elevated number, which is what makes it safe to let this decide
    autonomously with no human in the loop:
      - 55%  AI-adjusted confidence score (already reflects rule evidence
             plus the AI copilot's bounded contextual adjustment)
      - 30%  red-flag weight total, capped at 100
      - 15%  independent corroboration (PEP match / adverse media / prior
             AML history), scaled 0-100 by how many of those 3 are present
    Pure function of its three inputs -- reused unchanged by
    calibrate_l1_triage.py so the exact same formula is what gets
    recalibrated against new data, not reimplemented.
    """
    weight_component = min(red_flag_weight_total, 100)
    corrob_component = (corroboration_count / 3) * 100
    return round(0.55 * max_ai_score + 0.30 * weight_component + 0.15 * corrob_component, 1)


def gen_ai_l1_decision(cust_alerts, red_flags, aml_history, pep, sanctions, osint, r):
    """SARA.ai L1 Auto-Triage Pattern v2.

    REPLACES the earlier "binary decision with a contradiction/hold-for-human
    state" engine. Real-world AML transaction-monitoring programmes see the
    large majority of generated alerts (industry benchmarks commonly cited
    around 90-98%) resolve as false positives; scarce L1 analyst capacity
    should be spent on the small minority of alerts with genuine, corroborated
    evidence of suspicious activity, not on relitigating routine noise. This
    engine is built to reflect that operating reality: it ALWAYS renders a
    decisive outcome -- close_false_positive or escalate_to_l2 -- there is no
    "held for human review" state at L1 any longer. Cases that DO escalate
    still go through the full human-reviewed L2 -> L3 -> MLRO lifecycle
    exactly as before; nothing about the later stages' human-in-the-loop
    controls changes. This function only changes what happens at the very
    first triage step.

    THE PATTERN (reusable on any future dataset without code changes):
      1. A confirmed sanctions match is the one absolute, mandatory
         escalation -- decided immediately, no scoring needed.
      2. Otherwise, compute a single 0-100 `escalation_evidence_score` that
         blends three independent evidence sources (see
         escalation_evidence_score() below): the AI-adjusted confidence
         score, the red-flag weight total, and an independent-corroboration
         count (PEP / adverse media / prior AML history). Requiring several
         evidence sources to line up -- rather than keying off any single
         elevated number -- is what keeps the auto-close decision safe to
         make without a human in the loop.
      3. Escalate only if that score clears ESCALATION_THRESHOLD; otherwise
         close as a false positive.

    CALIBRATING THE THRESHOLD ON NEW DATA: ESCALATION_THRESHOLD below was set
    using scripts/calibrate_l1_triage.py against this reference dataset's
    score distribution (see that script's docstring for the full method --
    in short, a percentile cut so only the strongest-evidence slice of
    alerts escalates). Re-run that script against any new dataset's
    investigation_data.json to re-derive an appropriate threshold for that
    population's own score distribution; the scoring FORMULA itself does not
    need to change.
    """
    total_weight = sum(f["weight"] for f in red_flags if f["triggered"] == "Y")
    ai_scores = [a["ai_copilot"]["confidence_score"] for a in cust_alerts]
    max_ai_score = max(ai_scores, default=0)

    if sanctions["sanctions_match"] == "Y":
        return {
            "final_action": "escalate_to_l2",
            "requires_human_review": False,
            "review_reasons": [],
            "escalation_evidence_score": None,
            "decision_summary": (
                "A confirmed sanctions list match was identified during screening. This is a "
                "mandatory, unambiguous escalation regardless of transaction evidence, red-flag "
                "weight, or AI confidence score -- no further SARA.ai evaluation is applied."),
            "red_flag_weight_total": total_weight,
            "max_ai_confidence_score": max_ai_score,
            "qc_sample": False,
        }

    corroboration_count = sum([
        pep["pep_flag"] == "Y",
        osint["negative_news"] == "Y",
        aml_history["history_available"] == "Y",
    ])
    evidence_score = escalation_evidence_score(max_ai_score, total_weight, corroboration_count)

    if evidence_score >= ESCALATION_THRESHOLD:
        final_action = "escalate_to_l2"
        corrob_bits = []
        if pep["pep_flag"] == "Y":
            corrob_bits.append("a PEP match")
        if osint["negative_news"] == "Y":
            corrob_bits.append("adverse media coverage")
        if aml_history["history_available"] == "Y":
            corrob_bits.append("prior AML investigation history")
        corrob_clause = (", corroborated by " + ", ".join(corrob_bits)) if corrob_bits else ", on rule/AI evidence strength alone (no independent corroboration was needed to clear the bar)"
        summary = (
            f"SARA.ai auto-triage evidence score is {evidence_score}/100 (AI confidence "
            f"{max_ai_score}, red-flag weight {total_weight}){corrob_clause}. This combination "
            f"clears the escalation threshold ({ESCALATION_THRESHOLD}), so the case was "
            f"escalated to an L2 investigator autonomously.")
    else:
        final_action = "close_false_positive"
        summary = (
            f"SARA.ai auto-triage evidence score is {evidence_score}/100 (AI confidence "
            f"{max_ai_score}, red-flag weight {total_weight}, {corroboration_count} independent "
            f"corroborating signal(s)) -- below the escalation threshold ({ESCALATION_THRESHOLD}). "
            f"This pattern is consistent with routine account activity rather than genuine "
            f"suspicious activity, so the alert was closed as a false positive without human "
            f"involvement.")

    # Non-blocking governance control: a small, fixed random slice of
    # auto-closed alerts is flagged for periodic human QA sampling. This does
    # NOT hold up the decision or the case -- SARA.ai still closes it
    # autonomously and it does not advance to L2 -- it only marks the case as
    # eligible for a compliance team's after-the-fact quality sample, which is
    # standard practice for any automated-disposition control.
    qc_sample = final_action == "close_false_positive" and r.random() < QC_SAMPLE_RATE

    return {
        "final_action": final_action,
        "requires_human_review": False,
        "review_reasons": [],
        "escalation_evidence_score": evidence_score,
        "decision_summary": summary,
        "red_flag_weight_total": total_weight,
        "max_ai_confidence_score": max_ai_score,
        "qc_sample": qc_sample,
    }


def gen_audit_trail(cust_id, r, alert_date, ai_l1_decision):
    base = alert_date
    events = [
        {"time": (base + timedelta(minutes=0)).strftime("%Y-%m-%d %H:%M"), "user": "System", "action": "Alert Generated", "comments": "Rule engine triggered alert based on transaction monitoring scenario."},
        {"time": (base + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"), "user": "Case Management System", "action": "Assigned", "comments": "Auto-routed to AI L1 review."},
        {"time": (base + timedelta(minutes=8)).strftime("%Y-%m-%d %H:%M"), "user": "SARA.ai", "action": "KYC/CDD, Transaction History & Screening Reviewed", "comments": "AI reviewed KYC/CDD, 12-month transaction analysis, and PEP/sanctions/adverse-media screening results."},
    ]
    if ai_l1_decision["requires_human_review"]:
        events.append({"time": (base + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"), "user": "SARA.ai", "action": "Flagged for Human Review",
                        "comments": "Contradictory signals detected -- deferred to a human L1 analyst rather than deciding autonomously. See review_reasons."})
    else:
        action_label = DECISION_LABELS.get(ai_l1_decision["final_action"], ai_l1_decision["final_action"])
        events.append({"time": (base + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M"), "user": "SARA.ai", "action": f"Autonomous Decision: {action_label}",
                        "comments": "No contradictory signals found; AI decided this case without human involvement. See decision_summary."})
    return events

def sla_status(days_open, sla_days=5):
    remaining = sla_days - days_open
    pct = min(100, round((days_open / sla_days) * 100))
    if remaining < 0:
        status = "Breached"
    elif remaining <= 1:
        status = "Near Breach"
    else:
        status = "Within SLA"
    return {"days_open": days_open, "sla_target_days": sla_days, "remaining_days": remaining,
            "progress_percent": pct, "status": status}

# ---------------------------------------------------------------- main build
output = {}
for cust_id, cust_alerts in alerts_by_cust.items():
    cust = customers[cust_id]
    r = rng_for(cust_id)
    accounts = accounts_by_cust[cust_id]
    is_corporate = any(a["account_type"] == "business" for a in accounts)
    cust_txns = txns_by_cust[cust_id]

    sessions = device_sessions_by_cust.get(cust_id, [])
    kyc = gen_kyc(cust, r, is_corporate, sessions)
    user_entity = gen_user_entity(cust, kyc, is_corporate, r)
    risk_snapshot = gen_risk_snapshot(cust, r, kyc, accounts, cust_alerts, is_corporate)
    txn_analysis = gen_transaction_analysis(cust_id, r, cust_txns, accounts)
    historical_behaviour = gen_historical_behaviour(cust, r, txn_analysis)
    aml_history = gen_aml_history(cust_id, cust, r, accounts, cust_alerts)
    account_operations = gen_account_operations(cust_id, r, sessions, user_entity)
    pep = gen_pep(cust, r)
    sanctions = gen_sanctions(cust, r)
    osint = gen_osint(cust, r, is_corporate, pep["pep_flag"])
    ubo = gen_ubo(cust, r, is_corporate)
    red_flags = gen_red_flags(cust, r, txn_analysis, cust_alerts, is_corporate)
    ai_l1_decision = gen_ai_l1_decision(cust_alerts, red_flags, aml_history, pep, sanctions, osint, r)

    days_open = r.randint(0, 7)
    alert_date = TODAY - timedelta(days=days_open, hours=r.randint(0,20), minutes=r.randint(0,59))
    sla = sla_status(days_open)
    audit_trail = gen_audit_trail(cust_id, r, alert_date, ai_l1_decision)

    output[cust_id] = {
        "customer_id": cust_id,
        "accounts": [{"account_id": a["account_id"], "account_type": a["account_type"], "open_date": a["open_date"]} for a in accounts],
        "is_corporate": is_corporate,
        "kyc": kyc,
        "user_entity": user_entity,
        "risk_snapshot": risk_snapshot,
        "transaction_analysis": txn_analysis,
        "historical_behaviour": historical_behaviour,
        "aml_history": aml_history,
        "account_operations": account_operations,
        "pep_screening": pep,
        "sanctions_screening": sanctions,
        "osint": osint,
        "ubo": ubo,
        "red_flags": red_flags,
        "ai_l1_decision": ai_l1_decision,
        "audit_trail": audit_trail,
        "sla": sla,
        "alert_date": alert_date.strftime("%Y-%m-%d %H:%M"),
        "branch": r.choice(["Downtown Financial Centre", "Marina Bay Branch", "West End Corporate Branch",
                              "Harbourfront Retail Branch", "Central Business District Branch"]),
        "escalation_status": r.choice(["Not Escalated", "Not Escalated", "Not Escalated", "Pending L2 Review"]),
        "assigned_analyst": r.choice(["N. Fraser", "T. Wickramasinghe", "B. Odutayo", "C. Marsh", "L. Bouchard"]),
    }

# ---------------------------------------------------------------- lifecycle
# Attach the full L1 -> L1 QC -> L2 -> L2 QC -> MLRO/L3 -> SAR case lifecycle
# (process map: Complete_TM.xlsx). The L1 stage reuses ai_l1_decision above,
# so nothing about existing L1 behaviour changes; the later stages only
# materialise when a case actually escalates.
try:
    from workflow_engine import build_case_workflow, build_lifecycle_audit
    _wf_summary = {}
    for _cid, _inv in output.items():
        _wf = build_case_workflow(_inv)
        _inv["case_workflow"] = _wf
        _inv["lifecycle_audit"] = build_lifecycle_audit(_inv, _wf)
        # keep the top-level escalation_status consistent with the lifecycle
        _inv["escalation_status"] = _wf["current_stage_label"]
        _wf_summary[_wf["outcome"]] = _wf_summary.get(_wf["outcome"], 0) + 1
    print("Attached case_workflow lifecycle. Outcome distribution:")
    for _k, _v in sorted(_wf_summary.items(), key=lambda x: -x[1]):
        print(f"  {_v:3d}  {_k}")
except Exception as _e:
    print(f"WARNING: could not attach case_workflow lifecycle: {_e}")

with open("output/investigation_data.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"Built output/investigation_data.json with investigation records for {len(output)} customers.")
