"""CVE database and Nuclei template updater."""

import asyncio
import logging
from datetime import datetime

import httpx

from db.database import async_session
from db import crud
from config import settings

logger = logging.getLogger("penstation.cve_updater")


async def update_nuclei_templates():
    """Update nuclei templates to latest version."""
    logger.info("Updating nuclei templates...")
    proc = await asyncio.create_subprocess_exec(
        settings.NUCLEI_BIN, "-update-templates",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    output = stdout.decode() + stderr.decode()
    if proc.returncode == 0:
        logger.info("Nuclei templates updated successfully")
    else:
        logger.error("Nuclei template update failed: %s", output[:500])
    return proc.returncode == 0


async def fetch_nvd_feed():
    """Fetch recent CVEs from NVD API and store in local DB."""
    logger.info("Fetching NVD CVE feed...")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 100,
        "pubStartDate": _days_ago_iso(7),
        "pubEndDate": _now_iso(),
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                logger.error("NVD API returned %d", resp.status_code)
                return 0

            data = resp.json()
            items = data.get("vulnerabilities", [])
            count = 0
            async with async_session() as session:
                for item in items:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    if not cve_id:
                        continue

                    descriptions = cve_data.get("descriptions", [])
                    desc = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    severity = "info"

                    # Try CVSS 3.1 first, then 3.0, then 2.0
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        metric_list = metrics.get(key, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = _score_to_severity(cvss_score)
                            break

                    published = cve_data.get("published", "")
                    pub_dt = None
                    if published:
                        try:
                            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                        except ValueError:
                            pass

                    await crud.upsert_cve(
                        session,
                        cve_id=cve_id,
                        description=desc,
                        cvss_score=cvss_score,
                        severity=severity,
                        published_at=pub_dt,
                        updated_at=datetime.utcnow(),
                    )
                    count += 1

            logger.info("Updated %d CVE entries from NVD", count)
            return count

    except Exception as e:
        logger.error("Failed to fetch NVD feed: %s", e)
        return 0


async def enrich_cve(cve_id: str) -> dict | None:
    """Fetch detailed CVE info from NVD for a specific CVE ID."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()
            items = data.get("vulnerabilities", [])
            if not items:
                return None

            cve_data = items[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            async with async_session() as session:
                await crud.upsert_cve(
                    session,
                    cve_id=cve_id,
                    description=desc,
                    cvss_score=cvss_score,
                    severity=_score_to_severity(cvss_score),
                    updated_at=datetime.utcnow(),
                )

            return {"cve_id": cve_id, "description": desc, "cvss_score": cvss_score}

    except Exception as e:
        logger.error("Failed to enrich CVE %s: %s", cve_id, e)
        return None


async def update_cve_database():
    """Full update: templates + NVD feed."""
    await update_nuclei_templates()
    await fetch_nvd_feed()


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _days_ago_iso(days: int) -> str:
    from datetime import timedelta
    dt = datetime.utcnow() - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT00:00:00.000")


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
