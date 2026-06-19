#!/usr/bin/env bash
#
# nf-scenario.sh - break / fix the AWS Network Firewall scenarios using
# ONLY the AWS CLI. No repo clone, no CDK, no Node. Paste this file into AWS
# CloudShell (or run it anywhere the AWS CLI is configured) and go.
#
# It mutates the already-deployed firewall directly, so it produces the same
# break/fix the CDK scenarioctl does, but without needing the project checked out.
# All resource ids are discovered at runtime, so it works on any deployment of
# this stack in the current account/region.
#
# Usage:
#   ./nf-scenario.sh status            # show which scenario (if any) is active
#   ./nf-scenario.sh activate <1|2|3>  # break a scenario
#   ./nf-scenario.sh revert   <1|2|3>  # fix it (back to baseline)
#   AWS_REGION=us-west-2 ./nf-scenario.sh activate 1
#
# Scenarios:
#   1  Domain deny list   - add the test endpoint's app NLB DNS name to the
#                           rg-domain TLS-SNI denylist
#   2  Stateless priority - invert the rg-stateless-priority allow/drop priorities
#                           (drops TCP 9142 to the test endpoint)
#   3  Asymmetric routing  - flip protected-subnet A egress to the other AZ's
#                           firewall endpoint and move the return route, so a
#                           flow's SYN and its return traverse different endpoints
#
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
FW_NAME="nf-devops-agent"
POLICY_NAME="nf-devops-agent-policy"
PROJECT_TAG="nf-devops-agent"

BOLD=$(printf '\033[1m'); GRN=$(printf '\033[32m'); YLW=$(printf '\033[33m')
RED=$(printf '\033[31m'); CYN=$(printf '\033[36m'); RST=$(printf '\033[0m')
say()  { printf "%s==>%s %s\n" "$CYN" "$RST" "$*"; }
ok()   { printf "  %s✓%s %s\n" "$GRN" "$RST" "$*"; }
warn() { printf "  %s!%s %s\n" "$YLW" "$RST" "$*"; }
die()  { printf "%s✗ %s%s\n" "$RED" "$*" "$RST" >&2; exit 1; }

aws --version >/dev/null 2>&1 || die "AWS CLI not found."
AWS="aws --region $REGION"

# Scenario 1 SNI target. By default, discover the test endpoint's app NLB DNS
# name from the NfTestEndpointStack output so the deny rule matches exactly what
# the probe hits (no hardcoded domain). Override with SAAS_DOMAIN=... if needed.
if [ -z "${SAAS_DOMAIN:-}" ]; then
  SAAS_DOMAIN="$($AWS cloudformation describe-stacks \
    --stack-name NfTestEndpointStack \
    --query "Stacks[0].Outputs[?OutputKey=='AppEndpointDns'||OutputKey=='AppEndpointDnsOut'].OutputValue | [0]" \
    --output text 2>/dev/null || true)"
fi
[ -z "${SAAS_DOMAIN:-}" ] || [ "$SAAS_DOMAIN" = "None" ] && SAAS_DOMAIN="${SAAS_DOMAIN:-}"
if [ -z "${SAAS_DOMAIN:-}" ] || [ "$SAAS_DOMAIN" = "None" ]; then
  die "Could not resolve the test endpoint DNS (NfTestEndpointStack AppEndpointDns). Set SAAS_DOMAIN=... explicitly."
fi

# --- shared discovery -------------------------------------------------------
get_update_token() { $AWS network-firewall describe-firewall --firewall-name "$FW_NAME" --query 'UpdateToken' --output text; }
rg_token() { # $1 = rule group name, $2 = type
  $AWS network-firewall describe-rule-group --rule-group-name "$1" --type "$2" --query 'UpdateToken' --output text;
}

wait_in_sync() {
  say "Waiting for the firewall to reach IN_SYNC (rule/policy changes apply to new flows; ~30-90s)"
  for _ in $(seq 1 40); do
    local s; s=$($AWS network-firewall describe-firewall --firewall-name "$FW_NAME" \
      --query 'FirewallStatus.ConfigurationSyncStateSummary' --output text 2>/dev/null || echo PENDING)
    printf "  %s sync=%s\n" "$(date +%T)" "$s"
    [ "$s" = "IN_SYNC" ] && { ok "Firewall IN_SYNC"; return 0; }
    sleep 8
  done
  warn "Still not IN_SYNC after the wait window; it may just need another minute."
}

# ============================ SCENARIO 1 ====================================
S1_PLACEHOLDER='drop tls $HOME_NET any -> $EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"blocked.placeholder.invalid"; startswith; nocase; endswith; msg:"S1 domain denylist (placeholder)"; flow:to_server, established; sid:2000001; rev:1;)
drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"blocked.placeholder.invalid"; startswith; endswith; msg:"S1 domain denylist HTTP (placeholder)"; flow:to_server, established; sid:2000011; rev:1;)'

s1_rules_with_domain() {
  # Suricata normalizes http.host to lowercase, so the http.host content MUST be
  # lowercase (NLB DNS names contain uppercase). The TLS SNI rule uses nocase.
  local saas_lc; saas_lc=$(printf '%s' "$SAAS_DOMAIN" | tr '[:upper:]' '[:lower:]')
  cat <<EOF
drop tls \$HOME_NET any -> \$EXTERNAL_NET any (ssl_state:client_hello; tls.sni; content:"$SAAS_DOMAIN"; startswith; nocase; endswith; msg:"S1 domain denylist (SaaS domain)"; flow:to_server, established; sid:2000002; rev:1;)
drop http \$HOME_NET any -> \$EXTERNAL_NET any (http.host; content:"$saas_lc"; startswith; endswith; msg:"S1 domain denylist HTTP (SaaS domain)"; flow:to_server, established; sid:2000012; rev:1;)
$S1_PLACEHOLDER
EOF
}

put_domain_rules() { # $1 = rules string
  local tok; tok=$(rg_token rg-domain STATEFUL)
  $AWS network-firewall update-rule-group --rule-group-name rg-domain --type STATEFUL \
    --update-token "$tok" \
    --rule-group "{\"RulesSource\":{\"RulesString\":$(printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')},\"StatefulRuleOptions\":{\"RuleOrder\":\"STRICT_ORDER\"}}" \
    >/dev/null
}

scenario1() { # $1 = activate|revert
  if [ "$1" = activate ]; then
    say "Scenario 1: adding $SAAS_DOMAIN to the rg-domain TLS-SNI denylist"
    put_domain_rules "$(s1_rules_with_domain)"
    ok "rg-domain now drops $SAAS_DOMAIN on its TLS SNI"
  else
    say "Scenario 1: removing $SAAS_DOMAIN from the rg-domain denylist (back to placeholder only)"
    put_domain_rules "$S1_PLACEHOLDER"
    ok "rg-domain restored to baseline (placeholder only)"
  fi
}

# ============================ SCENARIO 2 ====================================
stateless_rule_group_json() { # $1 = allow priority, $2 = drop priority
  cat <<EOF
{"RulesSource":{"StatelessRulesAndCustomActions":{"StatelessRules":[
{"Priority":$1,"RuleDefinition":{"Actions":["aws:pass"],"MatchAttributes":{"Protocols":[6],"Sources":[{"AddressDefinition":"10.0.0.0/16"}],"Destinations":[{"AddressDefinition":"0.0.0.0/0"}],"DestinationPorts":[{"FromPort":9142,"ToPort":9142}]}}},
{"Priority":$2,"RuleDefinition":{"Actions":["aws:drop"],"MatchAttributes":{"Protocols":[6],"Sources":[{"AddressDefinition":"10.0.0.0/16"}],"Destinations":[{"AddressDefinition":"0.0.0.0/0"}],"DestinationPorts":[{"FromPort":9142,"ToPort":9142}]}}}
],"CustomActions":[]}}}
EOF
}

scenario2() { # $1 = activate|revert
  local tok; tok=$(rg_token rg-stateless-priority STATELESS)
  if [ "$1" = activate ]; then
    say "Scenario 2: inverting rg-stateless-priority (allow 200 > drop 100, so drop wins on TCP 9142)"
    $AWS network-firewall update-rule-group --rule-group-name rg-stateless-priority --type STATELESS \
      --update-token "$tok" --rule-group "$(stateless_rule_group_json 200 100)" >/dev/null
    ok "Stateless priorities inverted (drop now precedes allow)"
  else
    say "Scenario 2: restoring rg-stateless-priority (allow 100 < drop 200)"
    $AWS network-firewall update-rule-group --rule-group-name rg-stateless-priority --type STATELESS \
      --update-token "$tok" --rule-group "$(stateless_rule_group_json 100 200)" >/dev/null
    ok "Stateless priorities restored (allow precedes drop)"
  fi
}

# ============================ SCENARIO 3 ====================================
discover_s3_routing() {
  VPC_ID=$($AWS ec2 describe-vpcs --filters "Name=tag:Project,Values=$PROJECT_TAG" --query 'Vpcs[0].VpcId' --output text)
  [ "$VPC_ID" != None ] || die "Could not find the sample VPC (tag Project=$PROJECT_TAG)."
  # Firewall endpoints per AZ.
  EP_A=$($AWS network-firewall describe-firewall --firewall-name "$FW_NAME" --query "FirewallStatus.SyncStates.\"${REGION}a\".Attachment.EndpointId" --output text)
  EP_B=$($AWS network-firewall describe-firewall --firewall-name "$FW_NAME" --query "FirewallStatus.SyncStates.\"${REGION}b\".Attachment.EndpointId" --output text)
  # Protected subnet A (the workload subnet), its CIDR, and its route table.
  PSA=$($AWS ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[?contains(Tags[?Key=='aws-cdk:subnet-name']|[0].Value,'protected') && AvailabilityZone=='${REGION}a'].SubnetId|[0]" --output text)
  PSA_CIDR=$($AWS ec2 describe-subnets --subnet-ids "$PSA" --query 'Subnets[0].CidrBlock' --output text)
  RT_A=$($AWS ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$PSA" --query 'RouteTables[0].RouteTableId' --output text)
  # Public subnet route tables per AZ (where the NAT-return routes live).
  local PUBA PUBB
  PUBA=$($AWS ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[?contains(Tags[?Key=='aws-cdk:subnet-name']|[0].Value,'public') && AvailabilityZone=='${REGION}a'].SubnetId|[0]" --output text)
  PUBB=$($AWS ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "Subnets[?contains(Tags[?Key=='aws-cdk:subnet-name']|[0].Value,'public') && AvailabilityZone=='${REGION}b'].SubnetId|[0]" --output text)
  PUB_RT_A=$($AWS ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$PUBA" --query 'RouteTables[0].RouteTableId' --output text)
  PUB_RT_B=$($AWS ec2 describe-route-tables --filters "Name=association.subnet-id,Values=$PUBB" --query 'RouteTables[0].RouteTableId' --output text)
  [ "$EP_A" != None ] && [ "$EP_B" != None ] && [ "$RT_A" != None ] && [ "$PUB_RT_A" != None ] && [ "$PUB_RT_B" != None ] \
    || die "Could not discover firewall endpoints / route tables."
}

# Move the workload-CIDR NAT-return route between public route tables. The
# return route for the workload subnet must live in the public subnet of the AZ
# its egress exits, targeting the workload's OWN-AZ firewall endpoint. Baseline:
# in public-A -> EP_A (symmetric). Scenario 3: in public-B -> EP_A (asymmetric,
# because egress now exits via EP_B but return comes back via EP_A, which never
# saw the SYN). Idempotent: deletes any existing copy in both tables first.
move_return_route() { # $1 = dest public route table, $2 = target endpoint
  $AWS ec2 delete-route --route-table-id "$PUB_RT_A" --destination-cidr-block "$PSA_CIDR" >/dev/null 2>&1 || true
  $AWS ec2 delete-route --route-table-id "$PUB_RT_B" --destination-cidr-block "$PSA_CIDR" >/dev/null 2>&1 || true
  $AWS ec2 create-route --route-table-id "$1" --destination-cidr-block "$PSA_CIDR" --vpc-endpoint-id "$2" >/dev/null
}

scenario3() { # $1 = activate|revert
  discover_s3_routing
  if [ "$1" = activate ]; then
    say "Scenario 3: make egress asymmetric — flip protected-A egress to the other-AZ endpoint ($EP_B) and move the return path so egress and return use different endpoints"
    $AWS ec2 replace-route --route-table-id "$RT_A" --destination-cidr-block 0.0.0.0/0 --vpc-endpoint-id "$EP_B" >/dev/null
    move_return_route "$PUB_RT_B" "$EP_A"
    ok "Egress -> $EP_B, return for $PSA_CIDR -> $EP_A (asymmetric: the SYN's endpoint never sees the return, so the handshake never completes)"
  else
    say "Scenario 3: restore symmetric routing — protected-A egress back to its own-AZ endpoint ($EP_A) and the symmetric return path"
    $AWS ec2 replace-route --route-table-id "$RT_A" --destination-cidr-block 0.0.0.0/0 --vpc-endpoint-id "$EP_A" >/dev/null
    move_return_route "$PUB_RT_A" "$EP_A"
    ok "Egress + return both -> $EP_A (symmetric)"
  fi
}

# ============================ STATUS ========================================
show_status() {
  say "Firewall configuration sync state"
  $AWS network-firewall describe-firewall --firewall-name "$FW_NAME" \
    --query 'FirewallStatus.ConfigurationSyncStateSummary' --output text
  say "Alarm states"
  $AWS cloudwatch describe-alarms \
    --query "MetricAlarms[?starts_with(AlarmName,'Alarm-')].[AlarmName,StateValue]" --output table
  say "Status page URL"
  $AWS cloudformation describe-stacks --stack-name NfStatusPageStack \
    --query "Stacks[0].Outputs[?OutputKey=='StatusPageUrl'].OutputValue" --output text 2>/dev/null || true
}

# ============================ main ==========================================
CMD="${1:-}"; ARG="${2:-}"
case "$CMD" in
  status) show_status ;;
  activate|revert)
    case "$ARG" in
      1) scenario1 "$CMD" ;;
      2) scenario2 "$CMD" ;;
      3) scenario3 "$CMD" ;;
      *) die "Usage: $0 $CMD <1|2|3>" ;;
    esac
    wait_in_sync
    cat <<EOF

${BOLD}Done.${RST} Watch the status page flip within a health-check cycle (~30s), and the
matching alarm move to ALARM (activate) or back to OK (revert) within 1-2 minutes.
Open the status page:  ./nf-scenario.sh status
EOF
    ;;
  *)
    cat <<EOF
${BOLD}nf-scenario.sh${RST} - break/fix the Network Firewall scenarios from the AWS CLI (no repo needed)

  ./nf-scenario.sh status            show sync state, alarms, status-page URL
  ./nf-scenario.sh activate <1|2|3>  break a scenario
  ./nf-scenario.sh revert   <1|2|3>  fix it

  1 = domain deny list (TLS SNI)   2 = stateless rule priority   3 = asymmetric routing
EOF
    ;;
esac
