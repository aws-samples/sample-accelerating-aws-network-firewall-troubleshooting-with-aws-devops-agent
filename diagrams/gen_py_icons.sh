#!/bin/bash
# Regenerate assets/status-page/nf_icons.py from the official AWS icon package.
# The status page imports this module to embed AWS architecture icons in the
# topology (shipped to the workload as a CDK S3 asset, too large for user data).
# Run from the diagrams/ directory: bash gen_py_icons.sh
set -e
ARCH="Icon-package/Architecture-Service-Icons_04302026"
RES="Icon-package/Resource-Icons_04302026"
OUTDIR="../assets/status-page"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/nf_icons.py"

declare -a KEYS=(EC2 NFW S3 ELB INET NAT CF IGW CW SNS LAMBDA AGENT AWS KEYSPACES)
declare -a PATHS=(
  "$ARCH/Arch_Compute/64/Arch_Amazon-EC2_64.svg"
  "$ARCH/Arch_Security-Identity/64/Arch_AWS-Network-Firewall_64.svg"
  "$ARCH/Arch_Storage/64/Arch_Amazon-Simple-Storage-Service_64.svg"
  "$ARCH/Arch_Networking-Content-Delivery/64/Arch_Elastic-Load-Balancing_64.svg"
  "$RES/Res_General-Icons/Res_48_Light/Res_Internet-alt1_48_Light.svg"
  "$RES/Res_Networking-Content-Delivery/Res_Amazon-VPC_NAT-Gateway_48.svg"
  "$ARCH/Arch_Networking-Content-Delivery/64/Arch_Amazon-CloudFront_64.svg"
  "$RES/Res_Networking-Content-Delivery/Res_Amazon-VPC_Internet-Gateway_48.svg"
  "$ARCH/Arch_Management-Tools/64/Arch_Amazon-CloudWatch_64.svg"
  "$ARCH/Arch_Application-Integration/64/Arch_Amazon-Simple-Notification-Service_64.svg"
  "$ARCH/Arch_Compute/64/Arch_AWS-Lambda_64.svg"
  "$ARCH/Arch_Management-Tools/64/Arch_AWS-DevOps-Agent_64.svg"
  "Icon-package/Architecture-Group-Icons_04302026/AWS-Cloud-logo_32.svg"
  "$ARCH/Arch_Databases/64/Arch_Amazon-Keyspaces_64.svg"
)

{
  echo '"""AWS architecture icon data URIs for the AWS Network Firewall status page.'
  echo ''
  echo 'Generated from diagrams/Icon-package via diagrams/gen_py_icons.sh. Shipped to the'
  echo 'workload instance as a CDK S3 asset (too large to inline in EC2 user data).'
  echo '"""'
  echo ''
  for i in "${!KEYS[@]}"; do
    key="${KEYS[$i]}"; path="${PATHS[$i]}"
    if [ ! -f "$path" ]; then echo "MISSING: $key -> $path" >&2; exit 1; fi
    b64=$(base64 < "$path" | tr -d '\n')
    echo "ICON_${key} = \"data:image/svg+xml;base64,${b64}\""
  done
} > "$OUT"

echo "wrote $OUT"
grep -c '^ICON_' "$OUT"
