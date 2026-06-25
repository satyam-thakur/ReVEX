from typing import Dict, Any, List, Tuple
import logging


class PackageSearchIndex:
    """Minimal index for ground truth label lookup."""
    
    def __init__(self, logger: logging.Logger = None):
        self.gt_index: Dict[Tuple[str, str, str], str] = {}
        self.logger = logger or logging.getLogger(__name__)

    def _normalize_package_name(self, pkg_name: str) -> List[str]:
        """Extract package name variants for flexible matching."""
        if not pkg_name:
            return []
        
        variants = [pkg_name.lower()]
        
        # Maven: group:artifact → extract artifact
        if ':' in pkg_name:
            variants.append(pkg_name.split(':')[-1].lower())
        
        # NPM scoped: @org/package → extract package
        if pkg_name.startswith('@') and '/' in pkg_name:
            variants.append(pkg_name.split('/')[-1].lower())
        
        # Go modules: github.com/org/repo → extract repo
        if '/' in pkg_name:
            variants.append(pkg_name.split('/')[-1].lower())
        
        return list(set(variants))

    def index_sbom(self, sbom_artifacts: List[Dict[str, Any]]):
        """No-op: SBOM search handled by SBOMPackageChecker with .txt file."""
        if self.logger:
            self.logger.info(f"Skipping SBOM indexing (handled by SBOMPackageChecker)")

    def index_ground_truth(self, ground_truth_data: List[Dict[str, Any]]):
        """Index ground truth labels for CVE validation."""
        for item in ground_truth_data:
            cve = item.get('effective_cve', '').lower()
            pkg = item.get('package', {}).get('name', '')
            version = item.get('package', {}).get('version', '')
            label = item.get('label', '').upper()
            
            variants = self._normalize_package_name(pkg)
            
            for variant in variants:
                # Index with version
                self.gt_index[(cve, variant, version)] = label
                # Index without version (fallback)
                self.gt_index[(cve, variant, '')] = label
        
        if self.logger:
            self.logger.info(f"Indexed {len(ground_truth_data)} ground truth entries")

    def search_ground_truth(self, cve_id: str, package_name: str, version: str = None) -> Tuple[str, str]:
        """Search ground truth label for CVE-package combination."""
        cve_lower = cve_id.lower()
        variants = self._normalize_package_name(package_name)
        
        # Try exact match with version first
        if version:
            for variant in variants:
                key = (cve_lower, variant, version)
                if key in self.gt_index:
                    return self.gt_index[key], f"Exact match: {variant}@{version}"
        
        # Fallback to version-agnostic match
        for variant in variants:
            key = (cve_lower, variant, '')
            if key in self.gt_index:
                return self.gt_index[key], f"Package match: {variant} (version-agnostic)"
        
        return 'NA', 'No ground truth found'
