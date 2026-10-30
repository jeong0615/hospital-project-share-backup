#!/bin/bash

# Load the Cloudflare API token into the current shell without printing it.
load_cloudflare_ssm_token() {
  local parameter_name="${CF_TOKEN_PARAM_NAME:-/hospital-dr/cloudflare/api-token}"
  local region="${CF_TOKEN_AWS_REGION:-ap-northeast-2}"
  local token

  if ! command -v aws >/dev/null 2>&1; then
    echo "[CONFIG ERROR] AWS CLI is required to read the Cloudflare token from SSM." >&2
    return 1
  fi

  # Ignore legacy tokens inherited from dr.env or the parent shell.
  unset CF_API_TOKEN CLOUDFLARE_API_TOKEN

  if ! token="$(aws --region "$region" ssm get-parameter \
    --name "$parameter_name" \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text 2>/dev/null)"; then
    echo "[CONFIG ERROR] Failed to read Cloudflare token from SSM parameter: ${parameter_name}." >&2
    return 1
  fi

  if [ -z "$token" ] || [ "$token" = "None" ]; then
    echo "[CONFIG ERROR] Cloudflare token is empty in SSM parameter: ${parameter_name}." >&2
    return 1
  fi

  export CLOUDFLARE_API_TOKEN="$token"
  unset token
}
