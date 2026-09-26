# CloudSentinel: Solution Writeup

### The Problem
Traditional CI/CD pipelines either block deployments with slow manual reviews or let costly, insecure Infrastructure-as-Code (IaC) slip into production. Teams face open ingress ports, unencrypted storage, over-provisioned compute, and high cloud bills without automated verification.

### What the Agent Reaches & Where It Stops
- **What it reaches:** CloudSentinel autonomously parses multi-format IaC (Terraform, CloudFormation), evaluates Cedar zero-trust security policies, executes isolated sandbox deployments, computes FinOps instance rightsizing, and generates atomic, non-destructive remediation diffs.
- **Where it stops:** The agent strictly enforces a human-in-the-loop gate. Destructive mutations and production deployment actions halt entirely until an authorized operator issues explicit approval (`READY_FOR_DEPLOYMENT`).

### Architecture & TrueForge Integration
- **Control Plane:** TrueForge Agent (`cloudsentinel-ai`) acts as the reasoning brain. It analyzes template intent, conducts FinOps cost modeling, coordinates remediation logic, and enforces human-approval boundaries.
- **Execution Engine:** A FastMCP server (`server.py`) exposing core operational tools: `scan_infrastructure`, `simulate_in_sandbox`, and `apply_remediation`.
- **Integration:** TrueForge interfaces with the execution engine to orchestrate scanning and sandbox validation through tool calls.

### Real vs. Mocked
- **Real:** Cedar-style policy evaluation engine, template AST parsing, unified git diff generation, automatic timestamped rollback backups (`.cloudguard/backups`), and local CLI/MCP inspector tooling.
- **Mocked:** AWS cloud resource synthesis is executed in-memory via Moto and Boto3. This provides zero-cost sandbox validation without provisioning live billing resources.

### Known Limitations
- Does not currently support dynamic runtime state drift detection against live deployed AWS infrastructure.
- Template remediation currently targets core compute, storage, and networking primitives (EC2, S3, Security Groups), with broader resource types planned.
