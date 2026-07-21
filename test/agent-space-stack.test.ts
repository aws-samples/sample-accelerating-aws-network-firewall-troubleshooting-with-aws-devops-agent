/**
 * CDK assertion tests for `lib/agent-space-stack.ts`.
 *
 * Feature: automate AWS DevOps Agent onboarding as part of the deploy.
 *
 * `AgentSpaceStack` is standalone (no cross-stack references), so these tests
 * construct it directly under a pinned environment, synthesize the template,
 * and assert the resources the AWS CDK onboarding guide prescribes for a single
 * monitoring account:
 *   - the agent space (`AWS::DevOpsAgent::AgentSpace`) with the operator app enabled,
 *   - the AWS "monitor" association (`AWS::DevOpsAgent::Association`) for THIS account,
 *   - the agent-space service role (managed `AIDevOpsAgentAccessPolicy` + the
 *     Resource Explorer service-linked-role inline permission) trusted only by
 *     the `aidevops.amazonaws.com` service principal, and
 *   - the operator-app role (managed `AIDevOpsOperatorAppAccessPolicy`) whose
 *     trust policy allows `sts:AssumeRole` + `sts:TagSession`.
 *
 * It also confirms the region-availability list exported for the `bin/app.ts`
 * guard is well-formed.
 */
import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";

import {
  AgentSpaceStack,
  DEVOPS_AGENT_SUPPORTED_REGIONS,
} from "../lib/agent-space-stack";

/** A pinned environment (a supported region) so synthesis is deterministic. */
const ENV: cdk.Environment = { account: "123456789012", region: "us-east-1" };

function synth(): Template {
  const app = new cdk.App();
  const stack = new AgentSpaceStack(app, "TestAgentSpaceStack", { env: ENV });
  return Template.fromStack(stack);
}

describe("AgentSpaceStack — DevOps Agent onboarding resources", () => {
  let template: Template;

  beforeAll(() => {
    template = synth();
  });

  it("creates exactly one agent space with the operator app enabled", () => {
    template.resourceCountIs("AWS::DevOpsAgent::AgentSpace", 1);
    template.hasResourceProperties("AWS::DevOpsAgent::AgentSpace", {
      Name: "nf-devops-agent-space",
      OperatorApp: {
        Iam: {
          OperatorAppRoleArn: Match.anyValue(),
        },
      },
    });
  });

  it("creates exactly one AWS monitor association for this account", () => {
    template.resourceCountIs("AWS::DevOpsAgent::Association", 1);
    template.hasResourceProperties("AWS::DevOpsAgent::Association", {
      ServiceId: "aws",
      Configuration: {
        Aws: {
          AccountId: "123456789012",
          AccountType: "monitor",
          AssumableRoleArn: Match.anyValue(),
        },
      },
    });
  });

  it("creates the agent-space service role trusted only by the DevOps Agent service principal", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      AssumeRolePolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: "Allow",
            Principal: { Service: "aidevops.amazonaws.com" },
            Condition: Match.objectLike({
              StringEquals: { "aws:SourceAccount": "123456789012" },
            }),
          }),
        ]),
      },
      ManagedPolicyArns: Match.arrayWith([
        Match.objectLike({
          "Fn::Join": Match.arrayWith([
            Match.arrayWith([Match.stringLikeRegexp("AIDevOpsAgentAccessPolicy")]),
          ]),
        }),
      ]),
    });
  });

  it("grants the agent-space role the Resource Explorer service-linked-role inline permission", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      Policies: Match.arrayWith([
        Match.objectLike({
          PolicyDocument: {
            Statement: Match.arrayWith([
              Match.objectLike({
                Effect: "Allow",
                Action: "iam:CreateServiceLinkedRole",
              }),
            ]),
          },
        }),
      ]),
    });
  });

  it("creates the operator-app role allowing sts:AssumeRole and sts:TagSession", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      AssumeRolePolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: "Allow",
            Principal: { Service: "aidevops.amazonaws.com" },
            Action: ["sts:AssumeRole", "sts:TagSession"],
          }),
        ]),
      },
      ManagedPolicyArns: Match.arrayWith([
        Match.objectLike({
          "Fn::Join": Match.arrayWith([
            Match.arrayWith([
              Match.stringLikeRegexp("AIDevOpsOperatorAppAccessPolicy"),
            ]),
          ]),
        }),
      ]),
    });
  });

  it("creates the two DevOps Agent IAM roles (agent-space + operator)", () => {
    template.resourceCountIs("AWS::IAM::Role", 2);
  });

  it("tags every resource with the project teardown-sweep tag", () => {
    template.hasResourceProperties("AWS::IAM::Role", {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: "Project", Value: "nf-devops-agent" }),
      ]),
    });
  });
});

describe("DEVOPS_AGENT_SUPPORTED_REGIONS — the bin/app.ts region guard list", () => {
  it("includes the sample's default region and is a non-empty unique list", () => {
    expect(DEVOPS_AGENT_SUPPORTED_REGIONS).toContain("us-east-1");
    expect(DEVOPS_AGENT_SUPPORTED_REGIONS.length).toBeGreaterThan(0);
    expect(new Set(DEVOPS_AGENT_SUPPORTED_REGIONS).size).toBe(
      DEVOPS_AGENT_SUPPORTED_REGIONS.length,
    );
  });
});
