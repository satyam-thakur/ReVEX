#!/bin/bash
# Function to derive standardized report name
# Rule: keep registry; replace '/' with '+'; drop chars from first ':' to before '@sha256'
# Final format: docker.io+anchore+test_images@sha256_<digest>.json

get_report_name_test() {
  local IMAGE=$1
  local BEFORE_AT="${IMAGE%@sha256:*}"
  local BASE_NO_TAG="${BEFORE_AT%%:*}"
  local BASE_PLUS=$(echo "$BASE_NO_TAG" | tr '/' '+')
  if [[ "$IMAGE" == *"@sha256:"* ]]; then
    local DIGEST_HEX="${IMAGE##*@sha256:}"
    echo "${BASE_PLUS}@sha256_${DIGEST_HEX}.json"
  else
    echo "${DIGEST_HEX}.json"
  fi
}

# Function for vulhub images: vulhub/nextjs:15.5.6 -> vulhub+nextjs@15.5.6.json
# Rule: replace '/' with '+' and ':' with '@'
get_vulhub_report_name() {
  local IMAGE=$1
  local TRANSFORMED=$(echo "$IMAGE" | tr '/' '+' | tr ':' '@')
  echo "${TRANSFORMED}.json"
}

# Main function: auto-detect and use appropriate naming function
get_report_name() {
  local IMAGE=$1
  if [[ "$IMAGE" == *"vulhub"* ]]; then
    get_vulhub_report_name "$IMAGE"
  else
    get_report_name_test "$IMAGE"
  fi
}
