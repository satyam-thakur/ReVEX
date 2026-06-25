"""
Advanced Metrics Calculation for Vulnerability Scanner Evaluation
Calculates Precision, Recall, F1, F2, variance metrics, and scanner overlap analysis
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


def load_evaluation_results(base_dir: Path) -> tuple:
    """Load existing evaluation results"""
    results_dir = base_dir / "evaluation_results_cve_only"
    
    with open(results_dir / "accumulated_cve_only_summary.json", 'r', encoding='utf-8') as f:
        summaries = json.load(f)
    
    with open(results_dir / "all_scanners_cve_only.json", 'r', encoding='utf-8') as f:
        all_images = json.load(f)
    
    return summaries, all_images


def calculate_precision_recall_f_scores(summary: Dict) -> Dict:
    """Calculate Precision, Recall, F1, F2 scores"""
    tp = summary['total_tp_detected']
    fp = summary['total_fp_detected']
    fn = summary['total_fn_missed']
    
    # Precision
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    
    # Recall (same as DHR)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    # F1-Score (harmonic mean of precision and recall)
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # F2-Score (weighs recall higher than precision)
    beta = 2
    f2 = (1 + beta**2) * (precision * recall) / ((beta**2 * precision) + recall) if ((beta**2 * precision) + recall) > 0 else 0.0
    
    # False Positive Rate (among labeled FPs)
    fpr = fp / (fp + summary['total_fp_labels'] - fp) if summary['total_fp_labels'] > 0 else 0.0
    
    # False Negative Rate
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "f2_score": f2,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr
    }


def calculate_per_image_statistics(scanner_name: str, per_image_data: List[Dict]) -> Dict:
    """Calculate per-image variance and percentile statistics"""
    # Filter only this scanner's images
    scanner_images = [img for img in per_image_data if img['scanner'] == scanner_name]
    
    if not scanner_images:
        return {}
    
    # Extract DHR values
    all_dhrs = [img['detection_hit_ratio'] for img in scanner_images]
    non_zero_dhrs = [dhr for dhr in all_dhrs if dhr > 0]
    
    # Calculate statistics
    mean_dhr = sum(all_dhrs) / len(all_dhrs) if all_dhrs else 0.0
    mean_non_zero = sum(non_zero_dhrs) / len(non_zero_dhrs) if non_zero_dhrs else 0.0
    
    # Standard deviation
    if len(all_dhrs) > 1:
        variance = sum((x - mean_dhr) ** 2 for x in all_dhrs) / len(all_dhrs)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_dhr if mean_dhr > 0 else 0.0
    else:
        std_dev = 0.0
        cv = 0.0
    
    # Percentiles
    sorted_dhrs = sorted(all_dhrs)
    n = len(sorted_dhrs)
    
    def percentile(data, p):
        if not data:
            return 0.0
        k = (len(data) - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return data[int(k)]
        return data[int(f)] * (c - k) + data[int(c)] * (k - f)
    
    p25 = percentile(sorted_dhrs, 0.25)
    p50 = percentile(sorted_dhrs, 0.50)  # median
    p75 = percentile(sorted_dhrs, 0.75)
    
    # Min and Max
    min_dhr = min(all_dhrs) if all_dhrs else 0.0
    max_dhr = max(all_dhrs) if all_dhrs else 0.0
    
    # Count perfect and zero detections
    perfect_detections = sum(1 for dhr in all_dhrs if dhr == 1.0)
    zero_detections = sum(1 for dhr in all_dhrs if dhr == 0.0)
    
    return {
        "mean_dhr": mean_dhr,
        "mean_dhr_non_zero": mean_non_zero,
        "median_dhr": p50,
        "std_deviation": std_dev,
        "coefficient_of_variation": cv,
        "percentile_25": p25,
        "percentile_50": p50,
        "percentile_75": p75,
        "min_dhr": min_dhr,
        "max_dhr": max_dhr,
        "images_with_perfect_detection": perfect_detections,
        "images_with_zero_detection": zero_detections,
        "total_images": len(scanner_images)
    }


def calculate_scanner_overlap(per_image_data: List[Dict]) -> Dict:
    """Calculate scanner overlap and Jaccard similarity"""
    # Group by image
    images_by_name = defaultdict(list)
    for img in per_image_data:
        images_by_name[img['image']].append(img)
    
    # For each image, collect detected CVEs by scanner
    scanner_names = ['trivy', 'grype', 'snyk', 'clair']
    
    overlap_stats = {
        "per_image_overlap": [],
        "aggregate_overlap": {},
        "jaccard_similarity": {}
    }
    
    # Aggregate CVE sets across all images
    aggregate_cves = {scanner: set() for scanner in scanner_names}
    
    for image_name, scanner_results in images_by_name.items():
        # Build CVE sets per scanner for this image
        image_cves = {}
        for result in scanner_results:
            scanner = result['scanner']
            detected = set(result.get('tp_detected_list', []))
            image_cves[scanner] = detected
            aggregate_cves[scanner].update(detected)
        
        # Calculate per-image overlap stats
        if len(image_cves) == 4:  # Only if all scanners present
            all_detected = set.union(*image_cves.values()) if image_cves.values() else set()
            common_to_all = set.intersection(*image_cves.values()) if image_cves.values() else set()
            
            overlap_stats["per_image_overlap"].append({
                "image": image_name,
                "total_unique_cves": len(all_detected),
                "common_to_all_scanners": len(common_to_all),
                "detected_by_scanner": {k: len(v) for k, v in image_cves.items()}
            })
    
    # Calculate aggregate overlap
    all_aggregate = set.union(*aggregate_cves.values()) if aggregate_cves.values() else set()
    common_aggregate = set.intersection(*aggregate_cves.values()) if aggregate_cves.values() else set()
    
    overlap_stats["aggregate_overlap"] = {
        "total_unique_cves_all_scanners": len(all_aggregate),
        "common_to_all_scanners": len(common_aggregate),
        "detected_by_scanner": {k: len(v) for k, v in aggregate_cves.items()},
        "scanner_sets": {k: sorted(list(v)) for k, v in aggregate_cves.items()}
    }
    
    # Calculate Jaccard similarity between scanner pairs
    jaccard_matrix = {}
    for i, scanner_a in enumerate(scanner_names):
        for scanner_b in scanner_names[i+1:]:
            set_a = aggregate_cves[scanner_a]
            set_b = aggregate_cves[scanner_b]
            
            intersection = len(set_a & set_b)
            union = len(set_a | set_b)
            jaccard = intersection / union if union > 0 else 0.0
            
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            jaccard_matrix[pair_key] = {
                "jaccard_similarity": jaccard,
                "intersection_size": intersection,
                "union_size": union,
                "only_in_a": len(set_a - set_b),
                "only_in_b": len(set_b - set_a)
            }
    
    overlap_stats["jaccard_similarity"] = jaccard_matrix
    
    # Calculate advanced similarity metrics
    # 1. Overlap Coefficient (Szymkiewicz-Simpson) - best for size imbalance
    overlap_coefficient_matrix = {}
    for i, scanner_a in enumerate(scanner_names):
        for scanner_b in scanner_names[i+1:]:
            set_a = aggregate_cves[scanner_a]
            set_b = aggregate_cves[scanner_b]
            
            intersection = len(set_a & set_b)
            min_size = min(len(set_a), len(set_b))
            overlap_coef = intersection / min_size if min_size > 0 else 0.0
            
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            overlap_coefficient_matrix[pair_key] = {
                "overlap_coefficient": overlap_coef,
                "intersection_size": intersection,
                "min_set_size": min_size,
                "smaller_scanner": scanner_a if len(set_a) <= len(set_b) else scanner_b,
                "interpretation": f"{overlap_coef*100:.1f}% of smaller scanner's findings are in larger scanner"
            }
    
    overlap_stats["overlap_coefficient"] = overlap_coefficient_matrix
    
    # 2. Dice Coefficient (Sørensen-Dice) - emphasizes positive agreement
    dice_coefficient_matrix = {}
    for i, scanner_a in enumerate(scanner_names):
        for scanner_b in scanner_names[i+1:]:
            set_a = aggregate_cves[scanner_a]
            set_b = aggregate_cves[scanner_b]
            
            intersection = len(set_a & set_b)
            sum_sizes = len(set_a) + len(set_b)
            dice = (2 * intersection) / sum_sizes if sum_sizes > 0 else 0.0
            
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            dice_coefficient_matrix[pair_key] = {
                "dice_coefficient": dice,
                "intersection_size": intersection,
                "sum_of_set_sizes": sum_sizes
            }
    
    overlap_stats["dice_coefficient"] = dice_coefficient_matrix
    
    # 3. Tversky Index - tunable asymmetric similarity
    # alpha=1, beta=1 -> Jaccard; alpha=0.5, beta=0.5 -> Dice
    # For vulnerability scanning: low alpha (extra detections aren't bad), 
    # high beta (missed vulnerabilities are worse)
    tversky_matrix = {}
    alpha = 0.3  # weight for unique items in set A (trusted scanner's extras)
    beta = 0.7   # weight for unique items in set B (test scanner's misses)
    
    for i, scanner_a in enumerate(scanner_names):
        for scanner_b in scanner_names[i+1:]:
            set_a = aggregate_cves[scanner_a]
            set_b = aggregate_cves[scanner_b]
            
            intersection = len(set_a & set_b)
            only_a = len(set_a - set_b)
            only_b = len(set_b - set_a)
            
            denominator = intersection + alpha * only_a + beta * only_b
            tversky = intersection / denominator if denominator > 0 else 0.0
            
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            tversky_matrix[pair_key] = {
                "tversky_index": tversky,
                "alpha": alpha,
                "beta": beta,
                "intersection_size": intersection,
                "only_in_a": only_a,
                "only_in_b": only_b
            }
    
    overlap_stats["tversky_index"] = tversky_matrix
    
    # 4. Pairwise Coverage (Asymmetric Containment) - for operational decisions
    pairwise_coverage_matrix = {}
    for i, scanner_a in enumerate(scanner_names):
        for scanner_b in scanner_names[i+1:]:
            set_a = aggregate_cves[scanner_a]
            set_b = aggregate_cves[scanner_b]
            
            intersection = len(set_a & set_b)
            
            # Coverage of A by B: how much of A's findings are in B
            coverage_a_by_b = intersection / len(set_a) if len(set_a) > 0 else 0.0
            # Coverage of B by A: how much of B's findings are in A
            coverage_b_by_a = intersection / len(set_b) if len(set_b) > 0 else 0.0
            
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            pairwise_coverage_matrix[pair_key] = {
                f"{scanner_b}_covers_{scanner_a}": coverage_a_by_b,
                f"{scanner_a}_covers_{scanner_b}": coverage_b_by_a,
                "intersection_size": intersection,
                f"{scanner_a}_total": len(set_a),
                f"{scanner_b}_total": len(set_b),
                "interpretation": {
                    f"{scanner_b}_covers_{scanner_a}": f"{coverage_a_by_b*100:.1f}% of {scanner_a}'s findings are also in {scanner_b}",
                    f"{scanner_a}_covers_{scanner_b}": f"{coverage_b_by_a*100:.1f}% of {scanner_b}'s findings are also in {scanner_a}"
                }
            }
    
    overlap_stats["pairwise_coverage"] = pairwise_coverage_matrix
    
    # 5. Summary Recommendations - recommended metrics based on use case
    summary_recommendations = {
        "description": "Recommended metrics based on scanner characteristics",
        "clair_comparisons": {},
        "large_scanner_comparisons": {}
    }
    
    # For Clair (smallest scanner) comparisons, use Overlap Coefficient
    for scanner in ['trivy', 'grype', 'snyk']:
        pair_key = f"clair_vs_{scanner}" if f"clair_vs_{scanner}" in overlap_coefficient_matrix else f"{scanner}_vs_clair"
        
        # Find the correct pair key
        if pair_key not in overlap_coefficient_matrix:
            for key in overlap_coefficient_matrix.keys():
                if 'clair' in key and scanner in key:
                    pair_key = key
                    break
        
        if pair_key in overlap_coefficient_matrix:
            overlap_data = overlap_coefficient_matrix[pair_key]
            jaccard_data = jaccard_matrix[pair_key]
            
            summary_recommendations["clair_comparisons"][f"clair_vs_{scanner}"] = {
                "recommended_metric": "overlap_coefficient",
                "overlap_coefficient": overlap_data["overlap_coefficient"],
                "jaccard_similarity": jaccard_data["jaccard_similarity"],
                "improvement_insight": f"Overlap ({overlap_data['overlap_coefficient']:.3f}) vs Jaccard ({jaccard_data['jaccard_similarity']:.3f}) - Overlap shows {overlap_data['overlap_coefficient']*100:.1f}% of Clair's findings are validated by {scanner}"
            }
    
    # For Trivy, Grype, Snyk comparisons, use Pairwise Coverage
    large_scanners = ['trivy', 'grype', 'snyk']
    for i, scanner_a in enumerate(large_scanners):
        for scanner_b in large_scanners[i+1:]:
            pair_key = f"{scanner_a}_vs_{scanner_b}"
            
            if pair_key in pairwise_coverage_matrix:
                coverage_data = pairwise_coverage_matrix[pair_key]
                jaccard_data = jaccard_matrix[pair_key]
                
                summary_recommendations["large_scanner_comparisons"][pair_key] = {
                    "recommended_metric": "pairwise_coverage",
                    f"{scanner_b}_covers_{scanner_a}": coverage_data[f"{scanner_b}_covers_{scanner_a}"],
                    f"{scanner_a}_covers_{scanner_b}": coverage_data[f"{scanner_a}_covers_{scanner_b}"],
                    "jaccard_similarity": jaccard_data["jaccard_similarity"],
                    "insight": f"{scanner_a.title()} covers {coverage_data[f'{scanner_a}_covers_{scanner_b}']*100:.1f}% of {scanner_b.title()}, while {scanner_b.title()} covers {coverage_data[f'{scanner_b}_covers_{scanner_a}']*100:.1f}% of {scanner_a.title()}"
                }
    
    overlap_stats["summary_recommendations"] = summary_recommendations
    
    return overlap_stats


def calculate_ensemble_metrics(per_image_data: List[Dict]) -> Dict:
    """Calculate ensemble method performance (union, intersection, majority voting)"""
    # Group by image
    images_by_name = defaultdict(list)
    for img in per_image_data:
        images_by_name[img['image']].append(img)
    
    ensemble_results = {
        "union": {"tp": 0, "fp": 0, "fn": 0},
        "intersection": {"tp": 0, "fp": 0, "fn": 0},
        "majority_2": {"tp": 0, "fp": 0, "fn": 0},
        "majority_3": {"tp": 0, "fp": 0, "fn": 0}
    }
    
    for image_name, scanner_results in images_by_name.items():
        if len(scanner_results) != 4:
            continue
        
        # Get ground truth for this image (same across all scanners)
        gt_tp = set(scanner_results[0].get('tp_detected_list', [])) | set(scanner_results[0].get('fn_missed_list', []))
        gt_fp = set(scanner_results[0].get('fp_detected_list', []))
        
        # Collect detections per CVE
        cve_detections = defaultdict(int)
        all_detected = set()
        
        for result in scanner_results:
            detected = set(result.get('tp_detected_list', [])) | set(result.get('fp_detected_list', []))
            all_detected.update(detected)
            for cve in detected:
                cve_detections[cve] += 1
        
        # Union (any scanner detects)
        union_detected = all_detected
        ensemble_results["union"]["tp"] += len(union_detected & gt_tp)
        ensemble_results["union"]["fp"] += len(union_detected & gt_fp)
        ensemble_results["union"]["fn"] += len(gt_tp - union_detected)
        
        # Intersection (all scanners detect)
        intersection_detected = {cve for cve, count in cve_detections.items() if count == 4}
        ensemble_results["intersection"]["tp"] += len(intersection_detected & gt_tp)
        ensemble_results["intersection"]["fp"] += len(intersection_detected & gt_fp)
        ensemble_results["intersection"]["fn"] += len(gt_tp - intersection_detected)
        
        # Majority voting (≥2 scanners)
        majority_2_detected = {cve for cve, count in cve_detections.items() if count >= 2}
        ensemble_results["majority_2"]["tp"] += len(majority_2_detected & gt_tp)
        ensemble_results["majority_2"]["fp"] += len(majority_2_detected & gt_fp)
        ensemble_results["majority_2"]["fn"] += len(gt_tp - majority_2_detected)
        
        # Majority voting (≥3 scanners)
        majority_3_detected = {cve for cve, count in cve_detections.items() if count >= 3}
        ensemble_results["majority_3"]["tp"] += len(majority_3_detected & gt_tp)
        ensemble_results["majority_3"]["fp"] += len(majority_3_detected & gt_fp)
        ensemble_results["majority_3"]["fn"] += len(gt_tp - majority_3_detected)
    
    # Calculate metrics for each ensemble method
    for method, counts in ensemble_results.items():
        tp, fp, fn = counts['tp'], counts['fp'], counts['fn']
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        ensemble_results[method].update({
            "precision": precision,
            "recall": recall,
            "f1_score": f1
        })
    
    return ensemble_results


def main():
    base_dir = Path(__file__).parent
    output_file = base_dir / "evaluation_results_cve_only" / "advanced_metrics.json"
    
    print("="*60)
    print("Advanced Metrics Calculation")
    print("="*60)
    
    # Load existing results
    print("\nLoading evaluation results...")
    summaries, all_images = load_evaluation_results(base_dir)
    
    advanced_metrics = {
        "metadata": {
            "description": "Advanced metrics for vulnerability scanner evaluation",
            "date_generated": "2026-01-05",
            "total_images_evaluated": summaries[0]['images_evaluated'] if summaries else 0
        },
        "per_scanner_metrics": [],
        "scanner_overlap_analysis": {},
        "ensemble_methods": {}
    }
    
    # Calculate metrics per scanner
    print("\nCalculating per-scanner metrics...")
    for summary in summaries:
        scanner_name = summary['scanner']
        print(f"  Processing {scanner_name}...")
        
        # Calculate precision, recall, F-scores
        pr_metrics = calculate_precision_recall_f_scores(summary)
        
        # Calculate per-image statistics
        variance_metrics = calculate_per_image_statistics(scanner_name, all_images)
        
        scanner_metrics = {
            "scanner": scanner_name,
            "basic_counts": {
                "images_evaluated": summary['images_evaluated'],
                "total_predicted": summary['total_predicted'],
                "tp_detected": summary['total_tp_detected'],
                "fp_detected": summary['total_fp_detected'],
                "fn_missed": summary['total_fn_missed'],
                "unlabeled_predicted": summary['total_unlabeled_predicted']
            },
            "classification_metrics": pr_metrics,
            "aggregate_metrics": {
                "detection_hit_ratio": summary['detection_hit_ratio'],
                "weighted_detection_hit_ratio": summary['weighted_detection_hit_ratio']
            },
            "per_image_statistics": variance_metrics
        }
        
        advanced_metrics["per_scanner_metrics"].append(scanner_metrics)
        
        print(f"    Precision: {pr_metrics['precision']:.4f}, Recall: {pr_metrics['recall']:.4f}, F1: {pr_metrics['f1_score']:.4f}, F2: {pr_metrics['f2_score']:.4f}")
    
    # Calculate scanner overlap
    print("\nCalculating scanner overlap and similarity metrics...")
    overlap_analysis = calculate_scanner_overlap(all_images)
    advanced_metrics["scanner_overlap_analysis"] = overlap_analysis
    
    print(f"  Total unique CVEs across all scanners: {overlap_analysis['aggregate_overlap']['total_unique_cves_all_scanners']}")
    print(f"  CVEs detected by all 4 scanners: {overlap_analysis['aggregate_overlap']['common_to_all_scanners']}")
    
    # Print Jaccard Similarity
    print("\n  Jaccard Similarity (traditional):")
    for pair, data in overlap_analysis['jaccard_similarity'].items():
        print(f"    {pair}: {data['jaccard_similarity']:.4f}")
    
    # Print Overlap Coefficient (best for Clair comparisons)
    print("\n  Overlap Coefficient (Szymkiewicz-Simpson) - handles size imbalance:")
    for pair, data in overlap_analysis['overlap_coefficient'].items():
        print(f"    {pair}: {data['overlap_coefficient']:.4f} ({data['interpretation']})")
    
    # Print Dice Coefficient
    print("\n  Dice Coefficient (Sørensen-Dice) - emphasizes positive agreement:")
    for pair, data in overlap_analysis['dice_coefficient'].items():
        print(f"    {pair}: {data['dice_coefficient']:.4f}")
    
    # Print Tversky Index
    print(f"\n  Tversky Index (α={overlap_analysis['tversky_index'][list(overlap_analysis['tversky_index'].keys())[0]]['alpha']}, β={overlap_analysis['tversky_index'][list(overlap_analysis['tversky_index'].keys())[0]]['beta']}):")
    for pair, data in overlap_analysis['tversky_index'].items():
        print(f"    {pair}: {data['tversky_index']:.4f}")
    
    # Print Pairwise Coverage
    print("\n  Pairwise Coverage (Asymmetric Containment):")
    for pair, data in overlap_analysis['pairwise_coverage'].items():
        for key, value in data['interpretation'].items():
            print(f"    {value}")
    
    # Print Summary Recommendations
    print("\n  --- SUMMARY RECOMMENDATIONS ---")
    summary_rec = overlap_analysis['summary_recommendations']
    
    print("\n  Clair Comparisons (using Overlap Coefficient due to size imbalance):")
    for pair, data in summary_rec['clair_comparisons'].items():
        print(f"    {pair}: {data['improvement_insight']}")
    
    print("\n  Large Scanner Comparisons (using Pairwise Coverage for directional insights):")
    for pair, data in summary_rec['large_scanner_comparisons'].items():
        print(f"    {pair}: {data['insight']}")
    
    # Calculate ensemble metrics
    print("\nCalculating ensemble method performance...")
    ensemble_metrics = calculate_ensemble_metrics(all_images)
    advanced_metrics["ensemble_methods"] = ensemble_metrics
    
    for method, metrics in ensemble_metrics.items():
        print(f"  {method}: Precision={metrics['precision']:.4f}, Recall={metrics['recall']:.4f}, F1={metrics['f1_score']:.4f}")
    
    # Save results
    print(f"\n✓ Saving advanced metrics to {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(advanced_metrics, f, indent=2)
    
    print("\n" + "="*60)
    print("Advanced Metrics Calculation Complete")
    print("="*60)


if __name__ == "__main__":
    main()
