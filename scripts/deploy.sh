#!/usr/bin/env bash
#
# deploy.sh - one-command deploy for the AWS Network Firewall + AWS DevOps Agent sample.
#
# Checks prerequisites, bootstraps CDK if needed, installs dependencies, deploys
# all stacks at the clean baseline (no scenario active), and prints the outputs
# and next steps. Safe to re-run (idempotent: CDK only changes what drifted).
#
# Usage:
#   bash scripts/deploy.sh                 # deploy to the cdk.json default region
#   AWS_REGION=us-west-2 bash scripts/deploy.sh
#   bash scripts/deploy.sh --skip-tests    # skip the local test run before deploy
#
set -euo pipefail

# ---- pretty output helpers ----
BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"; RED="$(printf '\033[31m')"
GRN="$(printf '\033[32m')"; YLW="$(printf '\033[33m')"; CYN="$(printf '\033[36m')"; RST="$(printf '\033[0m')"
step() { printf "\n%s==>%s %s%s%s\n" "$CYN" "$RST" "$BOLD" "$*" "$RST"; }
ok()   { printf "  %s✓%s %s\n" "$GRN" "$RST" "$*"; }
warn() { printf "  %s!%s %s\n" "$YLW" "$RST" "$*"; }
die()  { printf "\n%s✗ %s%s\n" "$RED" "$*" "$RST" >&2; exit 1; }

# ---- locate the project root (parent of this script's dir) ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    *) die "Unknown argument: $arg (supported: --skip-tests)" ;;
  esac
done

# ---------------------------------------------------------------------------
step "1/6  Checking prerequisites"
# ---------------------------------------------------------------------------
command -v node >/dev/null 2>&1 || die "Node.js is not installed. Install Node 18+ from https://nodejs.org and re-run."
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 18 ] || die "Node.js 18+ required (found $(node -v)). Upgrade and re-run."
ok "Node.js $(node -v)"

command -v npm >/dev/null 2>&1 || die "npm is not installed (it ships with Node.js)."
ok "npm $(npm -v)"

command -v aws >/dev/null 2>&1 || die "AWS CLI v2 is not installed. See https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
ok "AWS CLI $(aws --version 2>&1 | awk '{print $1}')"

# CDK is provided via the local devDependency (npx), so a global install is optional.
ok "AWS CDK via npx (local devDependency)"

# Verify AWS credentials resolve.
CALLER_JSON="$(aws sts get-caller-identity --output json 2>/dev/null)" \
  || die "AWS credentials are not configured or have expired. Configure them (aws configure / SSO / assumed role) and re-run."
ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).Account')"
CALLER_ARN="$(printf '%s' "$CALLER_JSON" | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).Arn')"
ok "AWS account $ACCOUNT_ID  ($CALLER_ARN)"

# Resolve the deploy region: AWS_REGION env > cdk.json awsRegion context > us-east-1.
CTX_REGION="$(node -p 'try{JSON.parse(require("fs").readFileSync("cdk.json","utf8")).context.awsRegion||""}catch(e){""}')"
REGION="${AWS_REGION:-${CTX_REGION:-us-east-1}}"
export AWS_REGION="$REGION" CDK_DEFAULT_ACCOUNT="$ACCOUNT_ID" CDK_DEFAULT_REGION="$REGION"
ok "Target region $REGION"

# ---------------------------------------------------------------------------
step "2/6  Installing dependencies"
# ---------------------------------------------------------------------------
if [ -d node_modules ] && [ package-lock.json -ot node_modules ]; then
  ok "node_modules present and up to date (skipping install)"
else
  npm ci >/dev/null 2>&1 || npm install >/dev/null 2>&1 || die "npm install failed."
  ok "Dependencies installed"
fi

# ---------------------------------------------------------------------------
step "3/6  Validating the project (compile$([ $SKIP_TESTS -eq 0 ] && echo ' + tests'))"
# ---------------------------------------------------------------------------
npx tsc --noEmit || die "TypeScript compile failed. Fix the errors above and re-run."
ok "TypeScript compiles"
if [ "$SKIP_TESTS" -eq 0 ]; then
  # Run the tests in-band and non-interactively, capturing output so that, on
  # failure, the actual jest error is shown rather than a generic message.
  # --runInBand uses a single process (no Jest worker pool): on some Node
  # versions a worker can be force-exited during teardown and make Jest return a
  # non-zero exit code even when every test passes, which would fail this gate
  # spuriously. Running in-band avoids that and is plenty fast for this suite.
  TEST_LOG="$(mktemp -t nf-deploy-tests.XXXXXX)"
  if npx jest --ci --runInBand </dev/null >"$TEST_LOG" 2>&1; then
    ok "All tests pass"
    rm -f "$TEST_LOG"
  else
    printf "\n%s---- test output ----%s\n" "$DIM" "$RST" >&2
    cat "$TEST_LOG" >&2
    printf "%s---------------------%s\n" "$DIM" "$RST" >&2
    rm -f "$TEST_LOG"
    die "Tests failed (output above). You can also run 'npm test' directly, or 'bash scripts/deploy.sh --skip-tests' to deploy without the local test run."
  fi
else
  warn "Skipping tests (--skip-tests)"
fi

# ---------------------------------------------------------------------------
step "4/6  Bootstrapping CDK (if needed)"
# ---------------------------------------------------------------------------
if aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" >/dev/null 2>&1; then
  ok "CDK already bootstrapped in $ACCOUNT_ID/$REGION"
else
  warn "CDK not bootstrapped in $ACCOUNT_ID/$REGION - bootstrapping now"
  npx cdk bootstrap "aws://$ACCOUNT_ID/$REGION" || die "cdk bootstrap failed."
  ok "CDK bootstrapped"
fi

# ---------------------------------------------------------------------------
step "5/6  Deploying all stacks (clean baseline, no scenario active)"
# ---------------------------------------------------------------------------
# Deploy every stack at the baseline context. The sample defaults to
# --require-approval never so the one-command deploy runs unattended. To review
# IAM / security-group changes interactively (recommended when adapting this for
# production), set REQUIRE_APPROVAL, e.g. REQUIRE_APPROVAL=broadening bash scripts/deploy.sh
# (valid CDK values: never | any-change | broadening).
REQUIRE_APPROVAL="${REQUIRE_APPROVAL:-never}"
npx cdk deploy --all --require-approval "$REQUIRE_APPROVAL" || die "cdk deploy failed. See the error above."
ok "All stacks deployed"

# ---------------------------------------------------------------------------
step "6/6  Deployment outputs"
# ---------------------------------------------------------------------------
get_output() { # $1 stack, $2 output key
  aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text 2>/dev/null
}
STATUS_URL="$(get_output NfStatusPageStack StatusPageUrl)"
AGENT_ROLE="$(get_output NfAgentIamStack AgentRoleArn)"
WEBHOOK_FN="$(get_output NfWebhookStack WebhookFunctionName)"
WEBHOOK_SECRET="$(get_output NfWebhookStack WebhookSecretName)"
INSTANCE_ID="$(get_output NfWorkloadStack WorkloadInstanceId)"
SCRIPT_DL="$(get_output NfScenarioScriptStack ScenarioScriptDownload)"
PAGE_USER="$(get_output NfWorkloadStack StatusPageUsername)"
PAGE_SECRET="$(get_output NfWorkloadStack StatusPagePasswordSecret)"
# Read the generated password from AWS Secrets Manager (never a CFN output).
# SAMPLE ONLY: this prints the page password to the terminal for convenience.
# In production / CI, do not echo secrets to stdout (they land in terminal
# history and build logs); fetch them from AWS Secrets Manager when needed.
PAGE_PASS="$(aws secretsmanager get-secret-value --secret-id "${PAGE_SECRET:-nf-devops-agent-statuspage-login}" --region "$REGION" --query SecretString --output text 2>/dev/null)"

cat <<EOF

${GRN}${BOLD}============================================================${RST}
${GRN}${BOLD}  Deployment complete - clean baseline, no scenario active${RST}
${GRN}${BOLD}============================================================${RST}

  ${BOLD}Status page:${RST}  ${STATUS_URL:-<NfStatusPageStack StatusPageUrl>}
  ${BOLD}Page login:${RST}   ${PAGE_USER:-admin} / ${PAGE_PASS:-<read from Secrets Manager: nf-devops-agent-statuspage-login>}
  ${BOLD}Agent role:${RST}   ${AGENT_ROLE:-<NfAgentIamStack AgentRoleArn>}
  ${BOLD}Webhook fn:${RST}   ${WEBHOOK_FN:-nf-devops-agent-webhook}
  ${BOLD}Webhook secret:${RST} ${WEBHOOK_SECRET:-nf-devops-agent-webhook-credentials}
  ${BOLD}Workload:${RST}     ${INSTANCE_ID:-<NfWorkloadStack WorkloadInstanceId>}

${BOLD}NEXT STEPS${RST}
  1. Open the status page above and sign in with the page login. All three
     scenarios should read green.
  2. Connect AWS DevOps Agent (manual, one time):
       - Create an Agent Space and grant it the agent role above.
       - Configure the DevOps Agent webhook, then open the status page's
         "Configure webhook" link, paste the webhook URL + signing secret, and
         save. The page writes them to Secrets Manager for you (no AWS CLI).
       - Send a test event to the '${WEBHOOK_FN:-nf-devops-agent-webhook}' AWS Lambda function; a 200 confirms the path.
  3. Break / fix a scenario from CloudShell with the published script (no repo needed):
       ${SCRIPT_DL:-aws s3 cp s3://nf-devops-agent-scripts-<account>-<region>/nf-scenario.sh nf-scenario.sh && chmod +x nf-scenario.sh}
       ./nf-scenario.sh activate 1   # break
       ./nf-scenario.sh revert 1     # fix
     Or, from this cloned repo:
       npm run scenario activate 1   # break
       npm run scenario revert 1     # fix
     (repeat for 2 and 3; only one scenario active at a time)
  4. Tear everything down when done:
       bash scripts/destroy.sh

  Full walkthrough: blog/draft.md   Operator reference: runbook/runbook.md
${DIM}------------------------------------------------------------${RST}
EOF
