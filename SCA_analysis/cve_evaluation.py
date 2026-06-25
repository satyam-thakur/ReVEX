import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


def load_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _is_cve(cve: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve.upper()))


def extract_trivy_cves(report: dict) -> Set[str]:
    cves: Set[str] = set()
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID")
            if isinstance(cve_id, str) and _is_cve(cve_id):
                cves.add(cve_id.upper())
    return cves


def extract_grype_cves(report: dict) -> Set[str]:
    cves: Set[str] = set()
    for match in report.get("matches", []) or []:
        # Primary vulnerability ID
        vuln = match.get("vulnerability", {}) or {}
        cve_id = vuln.get("id")
        if isinstance(cve_id, str) and _is_cve(cve_id):
            cves.add(cve_id.upper())
        
        # Related vulnerabilities
        for related in match.get("relatedVulnerabilities", []) or []:
            related_id = related.get("id")
            if isinstance(related_id, str) and _is_cve(related_id):
                cves.add(related_id.upper())
    return cves


def extract_snyk_cves(report: dict) -> Set[str]:
    cves: Set[str] = set()
    for vuln in report.get("vulnerabilities", []) or []:
        identifiers = vuln.get("identifiers", {}) or {}
        cve_list = identifiers.get("CVE") or []
        if isinstance(cve_list, str):
            cve_list = [cve_list]
        if isinstance(vuln.get("id"), str) and vuln["id"].upper().startswith("CVE-"):
            cve_list = list(cve_list) + [vuln["id"]]
        for cve_id in cve_list:
            if isinstance(cve_id, str) and _is_cve(cve_id):
                cves.add(cve_id.upper())
    return cves


def extract_clair_cves(report: dict) -> Set[str]:
    cves: Set[str] = set()
    # In the provided JSON, detailed vulnerabilities are in "vulnerabilities" map.
    # "package_vulnerabilities" maps package IDs to lists of vulnerability IDs.
    # We can just iterate over "vulnerabilities" to get all unique CVEs.
    vulns = report.get("vulnerabilities") or {}
    
    # Check if we are dealing with the map format (vulnerability ID -> details)
    if isinstance(vulns, dict):
        for v_data in vulns.values():
            # The CVE ID is usually in the name or we can check the ID itself if it is the CVE
            name = v_data.get("name")
            if isinstance(name, str) and _is_cve(name):
                cves.add(name.upper())
            # Sometimes the ID itself might be the CVE if name isn't
            v_id = v_data.get("id")
            if isinstance(v_id, str) and _is_cve(v_id):
                cves.add(v_id.upper())
    
    return cves


def extract_label_cves(labels: List[dict]) -> Tuple[Set[str], Set[str]]:
    tp: Set[str] = set()
    fp: Set[str] = set()
    for label in labels:
        raw_label = label.get("label") or label.get("verdict") or label.get("Label") or label.get("status") or ""
        raw_label = str(raw_label).strip().lower()
        is_tp = raw_label in {"tp", "truepositive", "true positive", "true"}
        is_fp = raw_label in {"fp", "falsepositive", "false positive", "false"}
        cve_id = label.get("vulnerability_id") or label.get("effective_cve") or label.get("id") or label.get("cve_id")
        if isinstance(cve_id, str) and _is_cve(cve_id):
            cve_up = cve_id.upper()
            if is_tp:
                tp.add(cve_up)
            elif is_fp:
                fp.add(cve_up)
    return tp, fp


def find_matches(scanner_dir: Path, labels_dir: Path) -> List[Tuple[Path, Path]]:
    matches: List[Tuple[Path, Path]] = []
    for scanner_file in scanner_dir.glob("*.json"):
        label_file = labels_dir / f"{scanner_file.stem}.json"
        if label_file.exists():
            matches.append((scanner_file, label_file))
    return matches


def evaluate_scanner(scanner_name: str, scanner_dir: Path, labels_dir: Path, extractor, output_base: Path) -> Tuple[Dict, List[Dict]]:
    matches = find_matches(scanner_dir, labels_dir)
    if not matches:
        return {}, []

    output_dir = output_base / scanner_name
    output_dir.mkdir(parents=True, exist_ok=True)

    per_image: List[Dict] = []

    for scan_file, label_file in matches:
        scan_report = load_json_file(scan_file)
        label_data = load_json_file(label_file)

        predicted = extractor(scan_report)
        tp_labels, fp_labels = extract_label_cves(label_data)

        tp_detected = predicted & tp_labels
        fp_detected = predicted & fp_labels
        fn_missed = tp_labels - predicted
        unlabeled_pred = predicted - (tp_labels | fp_labels)

        hits = len(tp_detected)
        misses = len(fn_missed)
        dhr = hits / (hits + misses) if (hits + misses) > 0 else 0.0

        per_image.append({
            "image": scan_file.stem,
            "scanner": scanner_name,
            "predicted_total": len(predicted),
            "tp_labels": len(tp_labels),
            "fp_labels": len(fp_labels),
            "hits": hits,
            "misses": misses,
            "detection_hit_ratio": dhr,
            "tp_detected": len(tp_detected),
            "fp_detected": len(fp_detected),
            "fn_missed": len(fn_missed),
            "unlabeled_predicted": len(unlabeled_pred),
            "tp_detected_list": sorted(tp_detected),
            "fp_detected_list": sorted(fp_detected),
            "fn_missed_list": sorted(fn_missed),
            "unlabeled_predicted_list": sorted(unlabeled_pred),
        })

    summary = {
        "scanner": scanner_name,
        "images_evaluated": len(per_image),
        "total_predicted": sum(i["predicted_total"] for i in per_image),
        "total_tp_labels": sum(i["tp_labels"] for i in per_image),
        "total_fp_labels": sum(i["fp_labels"] for i in per_image),
        "total_tp_detected": sum(i["tp_detected"] for i in per_image),
        "total_fp_detected": sum(i["fp_detected"] for i in per_image),
        "total_fn_missed": sum(i["fn_missed"] for i in per_image),
        "total_unlabeled_predicted": sum(i["unlabeled_predicted"] for i in per_image),
        "total_hits": sum(i["hits"] for i in per_image),
        "total_misses": sum(i["misses"] for i in per_image),
        "detection_hit_ratio": (
            sum(i["hits"] for i in per_image)
            / (sum(i["hits"] for i in per_image) + sum(i["misses"] for i in per_image))
            if (sum(i["hits"] for i in per_image) + sum(i["misses"] for i in per_image)) > 0
            else 0.0
        ),
    }

    with open(output_dir / f"{scanner_name}_cve_only_results.json", "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "per_image": per_image}, f, indent=2)

    return summary, per_image


def find_common_images(labels_dir: Path, scanner_dirs: Dict[str, Path]) -> Set[str]:
    """Find images that have GT labels and scan reports in all 4 scanners"""
    # Get all GT files
    gt_images = {f.stem for f in labels_dir.glob("*.json")}
    print(f"Found {len(gt_images)} images with GT labels")
    
    # Find images present in all scanner directories
    common_images = gt_images.copy()
    for scanner_name, scanner_dir in scanner_dirs.items():
        if scanner_dir.exists():
            scanner_images = {f.stem for f in scanner_dir.glob("*.json")}
            print(f"  {scanner_name}: {len(scanner_images)} scan reports")
            common_images &= scanner_images
        else:
            print(f"  {scanner_name}: directory not found")
            return set()  # If any scanner dir missing, no common images
    
    print(f"\n✓ {len(common_images)} images have GT labels AND scan reports in all 4 scanners")
    return common_images


def evaluate_scanner_filtered(scanner_name: str, scanner_dir: Path, labels_dir: Path, 
                              extractor, output_base: Path, valid_images: Set[str]) -> Tuple[Dict, List[Dict]]:
    """Evaluate only images in valid_images set"""
    output_dir = output_base / scanner_name
    output_dir.mkdir(parents=True, exist_ok=True)

    per_image: List[Dict] = []

    for image_name in sorted(valid_images):
        scan_file = scanner_dir / f"{image_name}.json"
        label_file = labels_dir / f"{image_name}.json"
        
        if not scan_file.exists() or not label_file.exists():
            continue
            
        scan_report = load_json_file(scan_file)
        label_data = load_json_file(label_file)

        predicted = extractor(scan_report)
        tp_labels, fp_labels = extract_label_cves(label_data)

        tp_detected = predicted & tp_labels
        fp_detected = predicted & fp_labels
        fn_missed = tp_labels - predicted
        unlabeled_pred = predicted - (tp_labels | fp_labels)

        hits = len(tp_detected)
        misses = len(fn_missed)
        dhr = hits / (hits + misses) if (hits + misses) > 0 else 0.0

        per_image.append({
            "image": scan_file.stem,
            "scanner": scanner_name,
            "predicted_total": len(predicted),
            "tp_labels": len(tp_labels),
            "fp_labels": len(fp_labels),
            "hits": hits,
            "misses": misses,
            "detection_hit_ratio": dhr,
            "tp_detected": len(tp_detected),
            "fp_detected": len(fp_detected),
            "fn_missed": len(fn_missed),
            "unlabeled_predicted": len(unlabeled_pred),
            "tp_detected_list": sorted(tp_detected),
            "fp_detected_list": sorted(fp_detected),
            "fn_missed_list": sorted(fn_missed),
            "unlabeled_predicted_list": sorted(unlabeled_pred),
        })

    summary = {
        "scanner": scanner_name,
        "images_evaluated": len(per_image),
        "total_predicted": sum(i["predicted_total"] for i in per_image),
        "total_tp_labels": sum(i["tp_labels"] for i in per_image),
        "total_fp_labels": sum(i["fp_labels"] for i in per_image),
        "total_tp_detected": sum(i["tp_detected"] for i in per_image),
        "total_fp_detected": sum(i["fp_detected"] for i in per_image),
        "total_fn_missed": sum(i["fn_missed"] for i in per_image),
        "total_unlabeled_predicted": sum(i["unlabeled_predicted"] for i in per_image),
        "total_hits": sum(i["hits"] for i in per_image),
        "total_misses": sum(i["misses"] for i in per_image),
        "detection_hit_ratio": (
            sum(i["hits"] for i in per_image)
            / (sum(i["hits"] for i in per_image) + sum(i["misses"] for i in per_image))
            if (sum(i["hits"] for i in per_image) + sum(i["misses"] for i in per_image)) > 0
            else 0.0
        ),
    }

    with open(output_dir / f"{scanner_name}_cve_only_results.json", "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "per_image": per_image}, f, indent=2)

    return summary, per_image


def main() -> None:
    base_dir = Path(__file__).parent.parent
    scanner_dir = Path(__file__).parent

    labels_dir = base_dir / "datasets" / "reconciled_data"
    trivy_dir = base_dir / "GithubActions" / "TrivyScan"
    grype_dir = base_dir / "GithubActions" / "GrypeScan"
    snyk_dir = base_dir / "GithubActions" / "SnykScan"
    clair_dir = base_dir / "GithubActions" / "ClairScan"

    output_base = scanner_dir / "evaluation_results_cve_only"
    output_base.mkdir(parents=True, exist_ok=True)

    # Find images with GT labels AND scan reports in all 4 scanners
    scanner_dirs = {
        "trivy": trivy_dir,
        "grype": grype_dir,
        "snyk": snyk_dir,
        "clair": clair_dir,
    }
    valid_images = find_common_images(labels_dir, scanner_dirs)
    
    if not valid_images:
        print("No images found with both GT labels and all 4 scan reports!")
        return

    scanners = [
        ("trivy", trivy_dir, extract_trivy_cves),
        ("grype", grype_dir, extract_grype_cves),
        ("snyk", snyk_dir, extract_snyk_cves),
        ("clair", clair_dir, extract_clair_cves),
    ]

    summaries: List[Dict] = []
    combined_rows: List[Dict] = []
    scanner_per_image: Dict[str, List[Dict]] = {}
    
    for name, sdir, extractor in scanners:
        if sdir.exists():
            print(f"\nEvaluating {name}...")
            summary, per_image = evaluate_scanner_filtered(name, sdir, labels_dir, extractor, output_base, valid_images)
            if summary:
                summaries.append(summary)
                scanner_per_image[name] = per_image
            if per_image:
                combined_rows.extend(per_image)

    # Calculate weighted detection hit ratio for each scanner
    print("\n" + "="*60)
    print("Calculating Weighted Detection Hit Ratios...")
    print("="*60)
    for summary in summaries:
        scanner_name = summary['scanner']
        images = scanner_per_image.get(scanner_name, [])
        
        # Average of each image's DHR, ignoring images with DHR=0
        hit_ratios = [img['detection_hit_ratio'] for img in images if img['detection_hit_ratio'] > 0]
        
        if hit_ratios:
            weighted_hit_ratio = sum(hit_ratios) / len(hit_ratios)
        else:
            weighted_hit_ratio = 0.0
        
        summary['weighted_detection_hit_ratio'] = weighted_hit_ratio
        
        print(f"\n{scanner_name}:")
        print(f"  Detection Hit Ratio: {summary['detection_hit_ratio']:.4f} ({summary['detection_hit_ratio']*100:.2f}%)")
        print(f"  Weighted DHR (avg of non-zero): {weighted_hit_ratio:.4f} ({weighted_hit_ratio*100:.2f}%)")
        print(f"  Images with DHR>0: {len(hit_ratios)}/{len(images)}")

    if summaries:
        print(f"\n✓ Saving results to {output_base / 'accumulated_cve_only_summary.json'}")
        with open(output_base / "accumulated_cve_only_summary.json", "w", encoding="utf-8") as f:
            json.dump(summaries, f, indent=2)

    if combined_rows:
        with open(output_base / "all_scanners_cve_only.json", "w", encoding="utf-8") as f:
            json.dump(combined_rows, f, indent=2)

        csv_fields = [
            "scanner",
            "image",
            "hits",
            "misses",
            "detection_hit_ratio",
            "tp_labels",
            "fp_labels",
            "tp_detected",
            "fp_detected",
            "fn_missed",
            "unlabeled_predicted",
            "predicted_total",
        ]
        with open(output_base / "all_scanners_cve_only.csv", "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields)
            writer.writeheader()
            for row in combined_rows:
                writer.writerow({field: row.get(field, "") for field in csv_fields})


if __name__ == "__main__":
    main()
