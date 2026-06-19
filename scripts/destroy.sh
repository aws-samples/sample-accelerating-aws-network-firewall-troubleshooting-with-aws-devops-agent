#!/usr/bin/env bash
#
# destroy.sh - tear down the entire AWS Network Firewall + AWS DevOps Agent sample.
#
# Reverts any active scenario to baseline first (so teardown starts clean), then
# runs `cdk destroy --all`, then a tag-based straggler sweep on
# Project=nf-devops-agent to catch anything a failed delete left behind.
#
# Usage:
#   bash scripts/destroy.sh           # prompts for confirmation
#   bash scripts/destroy.sh --yes     # no prompt (CI / unattended)
#   AWS_REGION=us-west-2 bash scripts/destroy.sh
#
set -euo pipefail

BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"; RED="$(printf '\033[31m')"
GRN="$(printf '\033[32m')"; YLW="$(printf '\033[33m')"; CYN="$(printf '\033[36m')"; RST="$(printf '\033[0m')"
step() { printf "\n%s==>%s %s%s%s\n" "$CYN" "$RST" "$BOLD" "$*" "$RST"; }
ok()   { printf "  %s✓%s %s\n" "$GRN" "$RST" "$*"; }
warn() { printf "  %s!%s %s\n" "$YLW" "$RST" "$*"; }
die()  { printf "\n%s✗ %s%s\n" "$RED" "$*" "$RST" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y) ASSUME_YES=1 ;;
    *) die "Unknown argument: $arg (supported: --yes)" ;;
  esac
done

step "Checking prerequisites"
command -v node >/dev/null 2>&1 || die "Node.js is not installed."
command -v aws  >/dev/null 2>&1 || die "AWS CLI is not installed."
CALLER_JSON="$(aws sts get-caller-identity --output json 2>/dev/null)" \
  || die "AWS credentials are not configured or have expired."
ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).Account')"
CTX_REGION="$(node -p 'try{JSON.parse(require("fs").readFileSync("cdk.json","utf8")).context.awsRegion||""}catch(e){""}')"
REGION="${AWS_REGION:-${CTX_REGION:-us-east-1}}"
export AWS_REGION="$REGION" CDK_DEFAULT_ACCOUNT="$ACCOUNT_ID" CDK_DEFAULT_REGION="$REGION"
ok "AWS account $ACCOUNT_ID, region $REGION"

[ -d node_modules ] || { warn "node_modules missing - installing"; npm ci >/dev/null 2>&1 || npm install >/dev/null 2>&1 || die "npm install failed."; }

if [ "$ASSUME_YES" -eq 0 ]; then
  printf "\n%sThis will DELETE the entire sample (VPC, firewall, NAT gateways, EC2, ALB, alarms, logs)%s\n" "$YLW" "$RST"
  printf "in account %s region %s.\n" "$ACCOUNT_ID" "$REGION"
  printf "Enter %sdestroy%s to confirm: " "$BOLD" "$RST"
  read -r REPLY
  [ "$REPLY" = "destroy" ] || die "Aborted (you entered '$REPLY')."
fi

# ---------------------------------------------------------------------------
step "Clearing firewall-endpoint routes (so the firewall can delete cleanly)"
# ---------------------------------------------------------------------------
# AWS refuses to delete a Network Firewall while any route table still targets
# one of its Gateway Load Balancer endpoints. Scenario 3 adds such a route, and
# when that break is introduced by hand in the console (as the walkthrough
# shows) CloudFormation never tracks it, so `cdk destroy` leaves it behind and
# the firewall delete fails. Proactively delete every route whose target is a
# firewall endpoint here, before teardown. This is idempotent and only touches
# routes that point at the firewall's own vpce-* endpoints.
FIREWALL_NAME="nf-devops-agent"
clear_firewall_routes() {
  local fw_json fw_vpc endpoints rtbs
  fw_json="$(aws network-firewall describe-firewall --firewall-name "$FIREWALL_NAME" --region "$REGION" --output json 2>/dev/null)" || { ok "No firewall found (nothing to clear)"; return 0; }
  fw_vpc="$(printf '%s' "$fw_json" | node -p 'try{JSON.parse(require("fs").readFileSync(0,"utf8")).Firewall.VpcId}catch(e){""}')"
  # Collect every firewall endpoint id (one per Availability Zone).
  endpoints="$(printf '%s' "$fw_json" | node -p 'try{const s=JSON.parse(require("fs").readFileSync(0,"utf8")).FirewallStatus.SyncStates||{};Object.values(s).map(v=>v&&v.Attachment&&v.Attachment.EndpointId).filter(Boolean).join(" ")}catch(e){""}')"
  [ -z "$fw_vpc" ] && { warn "Could not resolve firewall VPC; skipping route cleanup"; return 0; }
  [ -z "$endpoints" ] && { ok "Firewall has no endpoints to dereference"; return 0; }
  ok "Firewall $FIREWALL_NAME in $fw_vpc; endpoints: $endpoints"
  local removed=0
  for ep in $endpoints; do
    # Find route tables in the firewall VPC that have a route targeting this endpoint,
    # and the destination CIDR of that route, then delete each one.
    while IFS=$'\t' read -r rtb cidr; do
      [ -z "$rtb" ] && continue
      if aws ec2 delete-route --route-table-id "$rtb" --destination-cidr-block "$cidr" --region "$REGION" >/dev/null 2>&1; then
        ok "Removed route $cidr -> $ep from $rtb"; removed=$((removed+1))
      else
        warn "Could not remove route $cidr -> $ep from $rtb (it may already be gone)"
      fi
    done < <(aws ec2 describe-route-tables --region "$REGION" \
              --filters "Name=vpc-id,Values=$fw_vpc" \
              --query "RouteTables[].[RouteTableId, Routes[?GatewayId=='$ep'].DestinationCidrBlock]" \
              --output json 2>/dev/null \
              | node -e 'const a=JSON.parse(require("fs").readFileSync(0,"utf8"))||[];for(const [rtb,cidrs] of a){for(const c of (cidrs||[])){if(c)console.log(rtb+"\t"+c);}}' 2>/dev/null)
  done
  [ "$removed" -eq 0 ] && ok "No firewall-endpoint routes needed clearing"
  return 0
}
clear_firewall_routes

# ---------------------------------------------------------------------------
step "Tearing down (revert active scenario -> cdk destroy --all -> tag sweep)"
# ---------------------------------------------------------------------------
# The scenarioctl 'destroy' verb reverts any active scenario to baseline first,
# runs cdk destroy --all --force, then sweeps Project=nf-devops-agent.
npx ts-node src/scenarioctl/cli.ts destroy || die "Teardown reported errors (see above). Re-run after addressing them."

step "Done"
ok "Environment torn down. Re-run 'bash scripts/deploy.sh' to stand it back up."
