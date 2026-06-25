import json
from pathlib import Path
from typing import Dict, Tuple

BASE_DIR = Path(__file__).resolve().parents[1]
DATASET = BASE_DIR / "vul_analysis" / "datasets" / "vulhub_eval_2020_2025.json"
TRIVY_DIR = BASE_DIR / "GithubActions" / "TrivyScan"
GRYPE_DIR = BASE_DIR / "GithubActions" / "GrypeScan"
SNYK_DIR = BASE_DIR / "GithubActions" / "SnykScan"
CLAIR_DIR = BASE_DIR / "GithubActions" / "ClairScan"


def get_vulhub_report_name(image: str) -> str:
    transformed = image.replace("/", "+").replace(":", "@")
    return f"{transformed}.json"


def load_json(path: Path) -> Dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def scan_contains_cve_trivy(report: Dict, cve_id: str) -> bool:
    if not report or not isinstance(report, dict):
        return False
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            vid = vuln.get("VulnerabilityID")
            if isinstance(vid, str) and vid.upper() == cve_id:
                return True
    return False


def scan_contains_cve_grype(report: Dict, cve_id: str) -> bool:
    if not report or not isinstance(report, dict):
        return False
    for match in report.get("matches", []) or []:
        # Primary vulnerability ID
        vuln = match.get("vulnerability", {}) or {}
        vid = vuln.get("id")
        if isinstance(vid, str) and vid.upper() == cve_id:
            return True
        
        # Related vulnerabilities
        for related in match.get("relatedVulnerabilities", []) or []:
            related_id = related.get("id")
            if isinstance(related_id, str) and related_id.upper() == cve_id:
                return True
    return False


def scan_contains_cve_snyk(report: Dict, cve_id: str) -> bool:
    if not report or not isinstance(report, dict):
        return False
    for vuln in report.get("vulnerabilities", []) or []:
        identifiers = vuln.get("identifiers", {}) or {}
        cve_list = identifiers.get("CVE") or []
        if isinstance(cve_list, str):
            cve_list = [cve_list]
        if isinstance(vuln.get("id"), str) and vuln["id"].upper().startswith("CVE-"):
            cve_list = list(cve_list) + [vuln["id"]]
        for cve in cve_list:
            if isinstance(cve, str) and cve.upper() == cve_id:
                return True
    return False


def scan_contains_cve_clair(report: Dict, cve_id: str) -> bool:
    if not report or not isinstance(report, dict):
        return False
    
    # Check vulnerabilities dict (maps vulnerability ID to details)
    vulns = report.get("vulnerabilities") or {}
    if isinstance(vulns, dict):
        for v_data in vulns.values():
            if not isinstance(v_data, dict):
                continue
            # Check name field for CVE ID
            name = v_data.get("name")
            if isinstance(name, str) and name.upper() == cve_id:
                return True
            # Check id field for CVE ID
            v_id = v_data.get("id")
            if isinstance(v_id, str) and v_id.upper() == cve_id:
                return True
    
    # Check packages dict (CVEs may appear as package names)
    packages = report.get("packages") or {}
    if isinstance(packages, dict):
        for pkg_data in packages.values():
            if not isinstance(pkg_data, dict):
                continue
            # Check package name for CVE ID
            pkg_name = pkg_data.get("name")
            if isinstance(pkg_name, str) and cve_id in pkg_name.upper():
                return True
    
    # Check enrichments (might contain CVE details indexed by vuln ID)
    enrichments = report.get("enrichments") or {}
    if isinstance(enrichments, dict):
        for key, enrichment in enrichments.items():
            if not isinstance(enrichment, dict):
                continue
            # Check if enrichment key or data contains CVE
            if isinstance(key, str) and key.upper() == cve_id:
                return True
            # Check various fields in enrichment data
            for field in ["id", "name", "cve"]:
                val = enrichment.get(field)
                if isinstance(val, str) and val.upper() == cve_id:
                    return True
    
    return False


def check_single(entry: Dict) -> Tuple[bool, bool, bool, bool]:
    cve = entry.get("CVE_ID", "").upper()
    image = entry.get("image", "")
    report_name = get_vulhub_report_name(image)

    trivy_hit = False
    grype_hit = False
    snyk_hit = False
    clair_hit = False

    trivy_path = TRIVY_DIR / report_name
    if trivy_path.exists():
        trivy_hit = scan_contains_cve_trivy(load_json(trivy_path), cve)

    grype_path = GRYPE_DIR / report_name
    if grype_path.exists():
        grype_hit = scan_contains_cve_grype(load_json(grype_path), cve)

    snyk_path = SNYK_DIR / report_name
    if snyk_path.exists():
        snyk_hit = scan_contains_cve_snyk(load_json(snyk_path), cve)

    clair_path = CLAIR_DIR / report_name
    if clair_path.exists():
        clair_hit = scan_contains_cve_clair(load_json(clair_path), cve)

    return trivy_hit, grype_hit, snyk_hit, clair_hit


def main() -> None:
    data = load_json(DATASET)
    total = len(data)
    t_hits = g_hits = s_hits = c_hits = 0
    all_four = any_three = any_two = any_one = 0

    out_dir = Path(__file__).resolve().parent / "vulhub_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "cve_detection_report.csv"

    rows = []

    print("CVE_ID,Image,Trivy,Grype,Snyk,Clair")
    for entry in data:
        cve = entry.get("CVE_ID", "")
        image = entry.get("image", "")
        trivy_hit, grype_hit, snyk_hit, clair_hit = check_single(entry)
        
        if trivy_hit:
            t_hits += 1
        if grype_hit:
            g_hits += 1
        if snyk_hit:
            s_hits += 1
        if clair_hit:
            c_hits += 1
        
        hit_count = sum([trivy_hit, grype_hit, snyk_hit, clair_hit])
        if hit_count == 4:
            all_four += 1
        elif hit_count == 3:
            any_three += 1
        elif hit_count == 2:
            any_two += 1
        elif hit_count == 1:
            any_one += 1
        
        print(f"{cve},{image},{'YES' if trivy_hit else 'NO'},{'YES' if grype_hit else 'NO'},{'YES' if snyk_hit else 'NO'},{'YES' if clair_hit else 'NO'}")
        rows.append(
            [
                cve,
                image,
                "YES" if trivy_hit else "NO",
                "YES" if grype_hit else "NO",
                "YES" if snyk_hit else "NO",
                "YES" if clair_hit else "NO",
            ]
        )

    detected_by_any = total - (total - t_hits - g_hits - s_hits - c_hits + all_four + any_three + any_two + any_one)
    none_detected = total - all_four - any_three - any_two - any_one

    print("\nSummary:")
    print(f"Total CVEs: {total}")
    print(f"Trivy detected: {t_hits}/{total} ({t_hits/total:.2%})")
    print(f"Grype detected: {g_hits}/{total} ({g_hits/total:.2%})")
    print(f"Snyk detected: {s_hits}/{total} ({s_hits/total:.2%})")
    print(f"Clair detected: {c_hits}/{total} ({c_hits/total:.2%})")
    print(f"\nBy Scanner Combinations:")
    print(f"All 4 scanners: {all_four}/{total} ({all_four/total:.2%})")
    print(f"Any 3 scanners: {any_three}/{total} ({any_three/total:.2%})")
    print(f"Any 2 scanners: {any_two}/{total} ({any_two/total:.2%})")
    print(f"Only 1 scanner: {any_one}/{total} ({any_one/total:.2%})")
    print(f"None detected: {none_detected}/{total} ({none_detected/total:.2%})")

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        f.write("CVE_ID,Image,Trivy,Grype,Snyk,Clair\n")
        for row in rows:
            f.write(",".join(row) + "\n")
        f.write("\n")
        f.write("=== DETECTION SUMMARY ===\n")
        f.write(f"Scanner,Detected,Percentage\n")
        f.write(f"Trivy,{t_hits},{t_hits/total:.2%}\n")
        f.write(f"Grype,{g_hits},{g_hits/total:.2%}\n")
        f.write(f"Snyk,{s_hits},{s_hits/total:.2%}\n")
        f.write(f"Clair,{c_hits},{c_hits/total:.2%}\n")
        f.write("\n")
        f.write("=== COMBINATION SUMMARY ===\n")
        f.write(f"Combination,Count,Percentage\n")
        f.write(f"All 4 scanners,{all_four},{all_four/total:.2%}\n")
        f.write(f"Any 3 scanners,{any_three},{any_three/total:.2%}\n")
        f.write(f"Any 2 scanners,{any_two},{any_two/total:.2%}\n")
        f.write(f"Only 1 scanner,{any_one},{any_one/total:.2%}\n")
        f.write(f"None detected,{none_detected},{none_detected/total:.2%}\n")
    print(f"\nCSV saved to: {csv_path}")


if __name__ == "__main__":
    main()
