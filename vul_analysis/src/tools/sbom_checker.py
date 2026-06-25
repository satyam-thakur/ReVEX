import json
from typing import List, Dict, Any, Optional
import logging
import re
from pathlib import Path

class SBOMPackageChecker:
    """Check SBOM for package presence and version match using .txt SBOM format."""
    
    # Ecosystem mapping from VulnerableDependencyChecker
    SYS_STANDARD_MAPPING = {
        ".net": "nuget",
        "cargo": "cargo",
        "composer": "composer",
        "conan": "conan",
        "conda": "pypi",
        "deb": "deb",
        "dpkg": "deb",
        "go": "go",
        "go-module": "go",
        "golang": "go",
        "java": "maven",
        "maven": "maven",
        "node.js": "npm",
        "npm": "npm",
        "nuget": "nuget",
        "php": "composer",
        "pip": "pypi",
        "pypi": "pypi",
        "python": "pypi",
        "rpm": "rpm",
        "ruby": "rubygems",
        "rubygems": "rubygems",
        "rust": "cargo"
    }
    
    def __init__(self, sbom_txt_path=None, search_index=None, logger=None):
        self.search_index = search_index
        self.logger = logger or logging.getLogger(__name__)
        self.sbom_packages = []
        
        if sbom_txt_path:
            self._load_sbom_from_txt(sbom_txt_path)
    
    def _load_sbom_from_txt(self, sbom_path: str):
        """Parse .txt SBOM file format (Syft output)."""
        try:
            with open(sbom_path, 'r') as f:
                lines = f.readlines()
            
            # Skip header line
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                
                # Parse format: NAME VERSION TYPE
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0]
                    version = parts[1]
                    pkg_type = parts[2]
                    
                    system = self.SYS_STANDARD_MAPPING.get(pkg_type.lower(), pkg_type.lower())
                    
                    self.sbom_packages.append({
                        "name": name,
                        "version": version,
                        "type": pkg_type,
                        "system": system
                    })
            
            self.logger.info(f"Loaded {len(self.sbom_packages)} packages from SBOM: {sbom_path}")
        except Exception as e:
            self.logger.error(f"Failed to load SBOM from {sbom_path}: {e}")

    def _package_names_match(self, name1: str, name2: str) -> bool:
        """Check if two package names match (case-insensitive, flexible matching)."""
        if not name1 or not name2:
            return False
        
        n1 = name1.lower().strip()
        n2 = name2.lower().strip()
        
        # Direct match
        if n1 == n2:
            return True
        
        # Handle Go module paths
        if '/' in n1 and '/' in n2:
            # Compare last component
            if n1.split('/')[-1] == n2.split('/')[-1]:
                return True
        
        # Handle scoped packages (@org/package)
        if n1.replace('@', '').replace('/', '') == n2.replace('@', '').replace('/', ''):
            return True
        
        # Handle Maven groupId:artifactId
        if ':' in n1 or ':' in n2:
            parts1 = n1.split(':')
            parts2 = n2.split(':')
            if len(parts1) > 1 and len(parts2) > 1:
                return parts1[-1] == parts2[-1]  # Compare artifactId
        
        return False

    def __call__(self, package_name: str, version: str = "", top_k: int = 5) -> str:
        """Check if a package exists in the SBOM."""
        # Use direct SBOM packages if loaded
        if self.sbom_packages:
            matches = self._search_sbom_packages(package_name, version, top_k)
        elif self.search_index:
            matches = self.search_index.search_sbom(package_name, version=version, top_k=top_k)
        else:
            matches = []
        
        result = {"status": "FOUND" if matches else "NOT_FOUND", "package_count": len(matches), "packages": matches} if matches else {"status": "NOT_FOUND", "message": f"Package '{package_name}' not found in SBOM"}
        json_result = json.dumps(result, indent=2)
        if self.logger:
            self.logger.info(f"\\n{'='*40} [TOOL OUTPUT: SBOMPackageChecker] {'='*40}\\n{json_result}\\n{'='*95}")
        return json_result

    def _search_sbom_packages(self, package_name: str, version: str = "", top_k: int = 5) -> List[Dict[str, Any]]:
        """Search loaded SBOM packages."""
        matches = []
        
        for pkg in self.sbom_packages:
            if self._package_names_match(pkg['name'], package_name):
                match_info = {
                    "name": pkg['name'],
                    "version": pkg['version'],
                    "type": pkg['type'],
                    "system": pkg['system']
                }
                
                # Version match scoring
                if version:
                    if pkg['version'] == version:
                        match_info['version_match'] = 'exact'
                        matches.insert(0, match_info)  # Prioritize exact version matches
                    else:
                        match_info['version_match'] = 'different'
                        match_info['requested_version'] = version
                        matches.append(match_info)
                else:
                    matches.append(match_info)
        
        return matches[:top_k]

    def check(self, package_name: str, version: str = "", top_k: int = 5) -> Dict[str, Any]:
        if self.sbom_packages:
            matches = self._search_sbom_packages(package_name, version, top_k)
        elif self.search_index:
            matches = self.search_index.search_sbom(package_name, version=version, top_k=top_k)
        else:
            matches = []
        
        if not matches:
            return {"status": "NOT_FOUND", "message": f"Package '{package_name}' not found in SBOM"}
        return {"status": "FOUND", "package_count": len(matches), "packages": matches}

    def to_json(self, package_name: str, version: str = "", top_k: int = 5) -> str:
        return json.dumps(self.check(package_name, version, top_k), indent=2)
