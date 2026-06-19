/**
 * ScenarioScriptStack — publishes the CloudShell scenario driver
 * (`scripts/nf-scenario.sh`) into a deterministically named Amazon Simple
 * Storage Service (Amazon S3) bucket so an
 * operator can break/fix the scenarios straight from AWS CloudShell with two
 * commands and no repo clone, CDK, or Node.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Why this exists
 * ────────────────────────────────────────────────────────────────────────────
 * `scripts/nf-scenario.sh` is a pure-AWS-CLI driver that mutates the deployed
 * firewall directly (it discovers every resource id at runtime). Shipping it as
 * part of the deploy means an operator can be handed a fixed `aws s3 cp`
 * command instead of relying on a public GitHub raw URL that only resolves once
 * the sample repo is published. The deploy puts the script in S3; the operator
 * pulls it in CloudShell and runs it.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * Deterministic bucket name
 * ────────────────────────────────────────────────────────────────────────────
 * The bucket is named `nf-devops-agent-scripts-<account>-<region>`. Account
 * + region keep it globally unique while staying predictable, so the docs can
 * publish a copy-paste command. The exact `aws s3 cp ...` line is also emitted
 * as the `ScenarioScriptDownload` stack output (printed by `scripts/deploy.sh`).
 *
 * The bucket uses `autoDeleteObjects` + `DESTROY` removal so the teardown sweep
 * (Requirement 10) removes it cleanly, and blocks all public access (the object
 * is pulled with credentials in CloudShell, never anonymously).
 */
import * as cdk from "aws-cdk-lib";
import { RemovalPolicy, Tags } from "aws-cdk-lib";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import { Construct } from "constructs";
import * as path from "path";

import { PROJECT_TAG_KEY, PROJECT_TAG_VALUE } from "./network-stack";

/** Object key the script lands under in the bucket. */
const SCRIPT_KEY = "nf-scenario.sh";

/**
 * The scenario-script publishing stack. Exposes the bucket, the object key, and
 * the ready-to-paste CloudShell download command.
 */
export class ScenarioScriptStack extends cdk.Stack {
  /** The bucket the scenario script is published into. */
  public readonly bucket: s3.Bucket;
  /** The S3 URI of the published script (`s3://bucket/nf-scenario.sh`). */
  public readonly scriptS3Uri: string;
  /** A ready-to-paste `aws s3 cp ...` command for CloudShell. */
  public readonly downloadCommand: string;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Deterministic, predictable, globally unique bucket name so the docs can
    // hand the reader a fixed download command.
    const bucketName = `nf-devops-agent-scripts-${this.account}-${this.region}`;

    this.bucket = new s3.Bucket(this, "ScriptBucket", {
      bucketName,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      autoDeleteObjects: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Publish ONLY nf-scenario.sh from the repo's scripts/ directory. The
    // exclude/include pair keeps deploy.sh and destroy.sh out of the bucket.
    new s3deploy.BucketDeployment(this, "PublishScenarioScript", {
      destinationBucket: this.bucket,
      sources: [
        s3deploy.Source.asset(path.join(__dirname, "..", "scripts"), {
          exclude: ["*", `!${SCRIPT_KEY}`],
        }),
      ],
      // Replace the bucket contents so a re-deploy always ships the latest script.
      prune: true,
      retainOnDelete: false,
    });

    this.scriptS3Uri = `s3://${bucketName}/${SCRIPT_KEY}`;
    this.downloadCommand = `aws s3 cp ${this.scriptS3Uri} ${SCRIPT_KEY} && chmod +x ${SCRIPT_KEY}`;

    Tags.of(this).add(PROJECT_TAG_KEY, PROJECT_TAG_VALUE);
  }
}
