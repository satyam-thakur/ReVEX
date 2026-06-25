#!/usr/bin/env bash
set -euo pipefail

# Baseline SBOM flow: generate Syft SBOMs once and feed them to SBOM-capable scanners for CVE reports.
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONFIG="$ROOT_DIR/config/config.json"
REPORT_NAME_SCRIPT="$ROOT_DIR/.github/scripts/get_report_name.sh"

if [[ ! -f "$CONFIG" ]]; then
  echo "Config not found: $CONFIG" >&2
  exit 1
fi

if [[ ! -f "$REPORT_NAME_SCRIPT" ]]; then
  echo "Missing helper: $REPORT_NAME_SCRIPT" >&2
  exit 1
fi
source "$REPORT_NAME_SCRIPT"

CONFIG_SCANNERS=$(jq -r '.scanners[]' "$CONFIG" | xargs || true)
SCANNERS=${SCANNERS:-$CONFIG_SCANNERS}
DEFAULT_IMAGES=()
while IFS= read -r img; do
  [[ -n "$img" ]] && DEFAULT_IMAGES+=("$img")
done < <(jq -r '.images[]' "$CONFIG")
IMAGES=(${IMAGES_OVERRIDE:-"${DEFAULT_IMAGES[@]}"})

BATCH_START=${BATCH_START:-0}
BATCH_SIZE=${BATCH_SIZE:-${#IMAGES[@]}}
IMAGES=(${IMAGES[@]:$BATCH_START:$BATCH_SIZE})

contains_scanner() {
  local needle=" $1 "
  local haystack=" ${SCANNERS} "
  [[ "$haystack" == *"$needle"* ]]
}

NEEDED=(jq syft)
contains_scanner trivy && NEEDED+=(trivy)
contains_scanner grype && NEEDED+=(grype)
contains_scanner osv && NEEDED+=(osv-scanner)

DID_APT_UPDATE=0
apt_update_once() {
  if [[ $DID_APT_UPDATE -eq 0 ]]; then
    sudo apt-get update -qq
    DID_APT_UPDATE=1
  fi
}

install_tool() {
  case "$1" in
    jq)
      apt_update_once
      sudo apt-get install -y jq
      ;;
    syft)
      curl -sSfL --max-time 60 https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin v1.14.0
      ;;
    trivy)
      apt_update_once
      sudo apt-get install -y wget apt-transport-https gnupg lsb-release
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
      echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
      sudo apt-get update -qq
      sudo apt-get install -y trivy
      ;;
    grype)
      curl -sSfL --max-time 60 https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
      ;;
    osv-scanner)
      curl -sSfL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /tmp/osv-scanner
      sudo mv /tmp/osv-scanner /usr/local/bin/osv-scanner
      sudo chmod +x /usr/local/bin/osv-scanner
      ;;
    snyk)
      curl -sSfL --max-time 60 https://static.snyk.io/cli/latest/snyk-linux -o /tmp/snyk
      sudo mv /tmp/snyk /usr/local/bin/snyk
      sudo chmod +x /usr/local/bin/snyk
      ;;
    *)
      echo "Unknown tool $1" >&2
      return 1
      ;;
  esac
}

for bin in "${NEEDED[@]}"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Installing missing binary: $bin"
    install_tool "$bin"
  fi
done

BASE_OUT="$ROOT_DIR/SBOM_Scan"
SYFT_DIR="$BASE_OUT/Syft_sbom"
TRIVY_DIR="$BASE_OUT/TrivyScan"
GRYPE_DIR="$BASE_OUT/GrypeScan"
OSV_DIR="$BASE_OUT/OSVScan"
SNYK_DIR="$BASE_OUT/SnykScan"
mkdir -p "$SYFT_DIR" "$TRIVY_DIR" "$GRYPE_DIR" "$OSV_DIR" "$SNYK_DIR"

GH_SYFT_DIR="$ROOT_DIR/GithubActions/Syft_sbom"

find_sbom_files() {
  local report_name="$1"
  SBOM_SPDX=""
  SBOM_CDX=""
  for base in "$SYFT_DIR" "$GH_SYFT_DIR"; do
    [[ -d "$base" ]] || continue
    [[ -z "$SBOM_SPDX" && -f "$base/${report_name%.json}_spdx.json" ]] && SBOM_SPDX="$base/${report_name%.json}_spdx.json"
    [[ -z "$SBOM_CDX" && -f "$base/${report_name%.json}_cyclonedx.json" ]] && SBOM_CDX="$base/${report_name%.json}_cyclonedx.json"
  done
  return 0
}

if contains_scanner snyk; then
  echo "Snyk disabled for now; skipping auth and scans." >&2
fi

for IMAGE in "${IMAGES[@]}"; do
  REPORT_NAME=$(get_report_name "$IMAGE")
  echo "Processing $IMAGE -> $REPORT_NAME"

  find_sbom_files "$REPORT_NAME"

  if [[ -n "$SBOM_SPDX" ]]; then
    echo "Using existing SPDX SBOM: $SBOM_SPDX"
  else
    echo "No SPDX SBOM found for $IMAGE, skipping."
    continue
  fi

  if contains_scanner trivy; then
    OUT="$TRIVY_DIR/${REPORT_NAME%.json}_from_sbom.json"
    trivy sbom --format json --output "$OUT" --scanners vuln "$SBOM_SPDX" || echo "Trivy failed for $IMAGE" >&2
  fi

  if contains_scanner grype; then
    OUT="$GRYPE_DIR/${REPORT_NAME%.json}_from_sbom.json"
    grype sbom:"$SBOM_SPDX" --output json > "$OUT" || echo "Grype failed for $IMAGE" >&2
  fi

  if contains_scanner osv; then
    OUT="$OSV_DIR/${REPORT_NAME%.json}_from_sbom.json"
    osv-scanner --sbom "$SBOM_SPDX" --format json > "$OUT" 2>"${OUT%.json}.log" || echo "OSV failed for $IMAGE" >&2
  fi

  if contains_scanner snyk; then
    echo "Snyk scan skipped for $IMAGE (temporarily disabled)."
  fi

done

echo "SBOM-driven scans completed. Results are under SBOM_Scan/*."
