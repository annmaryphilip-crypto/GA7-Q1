from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any
import re

app = FastAPI()


@app.get("/")
def root():
    return {"message": "TDS GA7 Release Gate is live!"}


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):

    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    # -------------------------------------------------
    # 1. Permissions must be EXACTLY least privilege
    # -------------------------------------------------
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    actual_permissions = workflow.get("permissions", {})

    if actual_permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # -------------------------------------------------
    # 2. Pull request safety
    # -------------------------------------------------
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # -------------------------------------------------
    # 3. Tests / matrix / failFast
    # -------------------------------------------------
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # -------------------------------------------------
    # 4. Action pinning
    # -------------------------------------------------
    for action in workflow.get("actions", []):

        owner = action.get("owner", "")
        ref_value = action.get("ref", "")

        # Official actions owned by "actions" may use tags
        if owner == "actions":
            continue

        # Third-party actions MUST use a 40-character
        # lowercase hexadecimal commit SHA
        if not re.fullmatch(r"[0-9a-f]{40}", ref_value):
            violations.append("MUTABLE_ACTION")
            break

    # -------------------------------------------------
    # 5. Docker image must be multi-stage
    # -------------------------------------------------
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # -------------------------------------------------
    # 6. Container must run as non-root
    # -------------------------------------------------
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # -------------------------------------------------
    # 7. Secrets
    # -------------------------------------------------
    secret_mode = image.get("secretMode")

    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # -------------------------------------------------
    # 8. Critical vulnerabilities
    # -------------------------------------------------
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # -------------------------------------------------
    # 9. Image must be digest pinned
    # -------------------------------------------------
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # -------------------------------------------------
    # 10. Production requirements
    # -------------------------------------------------
    if target == "production":

        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    # -------------------------------------------------
    # Final decision
    # -------------------------------------------------
    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }
