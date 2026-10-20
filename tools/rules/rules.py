from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, get_type_hints
from urllib.parse import urlparse

import mcptypes.rule_type as vo
from constants import constants
from mcpconfig.config import mcp
from mcptypes import exception
from mcptypes.rule_type import TaskVO
from utils import rule, wsutils
from utils.debug import logger
from fastmcp import Context
from utils import utils
import re

from mcptypes import assets_tools_type as assets_vo
import constants.error_constants as error_constants
import json
from mcptypes.rule_type import CVEEntryVO



# Phase 1: Lightweight task summary resource

if constants.ENABLE_CCOW_API_TOOLS:
    
    @mcp.tool()
    def create_support_ticket(subject: str, description: str, priority: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        PURPOSE:  
        - Create structured support tickets only after strict user review and explicit approval of all descriptions.  
        - Ticket creation MUST NOT occur without explicit user confirmation at every required step.  
        - Reduce user input errors and rework by ensuring clarity and completeness before ticket submission.

        MANDATORY CONDITIONS — NO STEP MAY BE SKIPPED OR BYPASSED:

        1. BEFORE TOOL ENTRY:  
        - The tool MUST generate a detailed, pre-filled plain-text description for the task or workflow.  
        - The user MUST review this description carefully.  
        - Ticket creation MUST be blocked until the user explicitly APPROVES this description.

        2. USER VERIFICATION:  
        - The user MUST be presented with the full pre-filled description.  
        - The user MUST either confirm its correctness or provide feedback for changes.  
        - The tool MUST update the description and priority per feedback and repeat this verification step as many times as needed.  
        - Skipping or auto-approving this step is strictly prohibited.

        3. FINAL APPROVAL & FORMATTING:  
        - After user approval of the plain text, the description MUST be converted into professional HTML format (bold headings, clear structure, spacing).  
        - The user MUST explicitly approve this final HTML-formatted description.  
        - The tool MUST block ticket creation until this final approval is given.  
        - Only the fully user-approved, HTML-formatted description MAY be used to create the support ticket.

        IMPORTANT:  
        **Under no circumstances shall the tool proceed to ticket creation without explicit user approval at all mandatory steps.**  
        The process must strictly enforce these approvals, preventing any premature or automatic ticket submissions.

        MANDATORY USER INPUTS:  
        - `subject` (str) — ticket title.  
        - `description` (str) — final user-approved, HTML-formatted description.  
        - `priority` (str) — ticket priority level.  
        **Valid values:** `"High"`, `"Medium"`, `"Low"` (case-sensitive).  
        The user MUST provide one of these values to proceed.

        RETURNS:  
        - A dictionary simulating the ticket creation response for integration or testing purposes.
        """

        try:
            request_body = {
                "subject": subject,
                "description": description,
                "priority": priority
            }

            response = rule.create_support_ticket_api(request_body, ctx)
            
            if not response:
                return {"error": "Failed to create support ticket with the specified details."}

            return response

        except Exception as e:
            return {
                "error": f"An error occurred while creating the support ticket: {e}"
            }
    
    @mcp.tool()
    def attach_rule_to_control(rule_id: str, assessment_name: str, control_id: str,create_evidence: bool = True, ctx: Context | None = None ) -> dict[str, Any]:

        """
        Attach a rule to a specific control in an assessment.

        🚨 CRITICAL EXECUTION BLOCKERS — DO NOT SKIP 🚨
        Before **any** part of this tool can run, five preconditions MUST be met:

        1. Control Verification:
        - You MUST verify the control exists in the assessment by calling `verify_control_in_assessment()`.
        - Verification must confirm the control is present, valid, and a leaf control.
        - If verification fails → STOP immediately. Do not proceed.

        2. Rule ID Resolution:
        - If `rule_id` is a valid UUID → proceed.
        - If `rule_id` is an alphabetic string → treat it as the rule name and resolve it to a UUID **using `fetch_cc_rule_by_name()`**.
        - If resolution fails or `rule_id` is still not a UUID after this step → STOP immediately.
        - Execution is STRICTLY PROHIBITED with a plain name.

        3. Rule Publish Validation:
        - You MUST check if the rule is published in ComplianceCow before proceeding.
        - If the rule is not published → STOP immediately.  
        - Published status is a hard requirement for attachment.

        4. Evidence Creation Acknowledgment:
        - Before proceeding, you MUST request confirmation from the user about `create_evidence`.
        - Ask: "Do you want to auto-generate evidence from the rule output? (default: True)"
        - Only proceed after the user explicitly acknowledges their choice.

        5. Override Acknowledgment:
        - If the control already has a rule attached, you MUST request user confirmation before overriding.
        - Ask: "This control already has a rule attached. Do you want to override it? (yes/no)"
        - Only proceed if the user explicitly confirms.

        RULE ATTACHMENT WORKFLOW:
        1. Perform control verification using `verify_control_in_assessment()` (MANDATORY).
        2. Resolve rule_id using the CRITICAL EXECUTION BLOCKERS above (use `fetch_cc_rule_by_name()` when needed).
        3. Validate that the rule is published in ComplianceCow.
        4. Confirm evidence creation preference from the user (acknowledgment REQUIRED).
        5. Check for existing rule attachments and request override acknowledgment if needed.
        6. Attach rule to control.
        7. Optionally create evidence for the control.

        ATTACHMENT OPTIONS:
        - create_evidence: Whether to create evidence along with rule attachment. 
        Must be confirmed by the user before proceeding.

        VALIDATION REQUIREMENTS:
        - Control must be verified and confirmed as a leaf control.
        - Rule must be published.
        - Rule ID must be a valid UUID.
        - Assessment and control must exist.
        - User must acknowledge override before replacing an existing rule.

        Args:
            rule_id: ID of the rule to attach (UUID). If an alphabetic string is provided, 
                    it MUST be resolved to a UUID using `fetch_cc_rule_by_name()` before the tool proceeds.
            assessment_name: Name of the assessment.
            control_id: ID of the control.
            create_evidence: Whether to create auto-generated evidence from the rule output (default: True).
                            ⚠️ MUST be confirmed by user acknowledgment before execution.

        Returns:
            Dict containing attachment status and details.
        """

        try:

            body = {
                "ruleId": rule_id,
                "createEvidence":create_evidence
            }
            
            response = rule.attach_rule_to_control_api(control_id,body, ctx)
            
            if response.get("success") or response.get("status") == "attached":
                result = {
                    "success": True,
                    "rule_id": rule_id,
                    "assessment_name": assessment_name,
                    "control_id": control_id,
                    "attachment_status": "attached",
                    "evidence_created": create_evidence,
                    "message": f"Rule '{rule_id}' successfully attached to control '{control_id}' in assessment '{assessment_name}'"
                }
                
                if create_evidence:
                    result["evidence_info"] = response.get("evidenceInfo", {})
                    result["message"] += " with evidence created."
                
                return result
            else:
                return {
                    "success": False,
                    "rule_id": rule_id,
                    "assessment_name": assessment_name,
                    "error": response.get("error", "Failed to attach rule to control"),
                    "message": f"Failed to attach rule '{rule_id}' to control '{control_id}'"
                }
                
        except Exception as e:
            return {
                "success": False,
                "rule_name": rule_id,
                "assessment_name": assessment_name,
                "error": f"Failed to attach rule to control: {str(e)}",
                "message": f"Error occurred while attaching rule to control"
            }

    @mcp.tool()
    def publish_rule(rule_name: str, cc_rule_name: str = None, ctx: Context | None = None) -> dict[str, Any]:
        """
        Publish a rule to make it available for ComplianceCow system.

        CRITICAL WORKFLOW RULES:
        - **MANDATORY: Check rule status to ensure rule is fully developed before publishing**
        - MUST FOLLOW THESE STEPS EXACTLY
        - DO NOT ASSUME OR SKIP ANY STEPS
        - APPLICATIONS FIRST, THEN RULE
        - WAIT FOR USER AT EACH STEP
        - NO SHORTCUTS OR BYPASSING ALLOWED

        RULE PUBLISHING HANDLING:

        WHEN TO USE:
        - After successful rule creation
        - User wants to make rule available for others
        - Rule has been tested and validated

        WORKFLOW (step-by-step with user confirmation):

        1. Fetch applications and check status
        - Call fetch_applications() to get available applications
        - Extract appTypes from ALL tasks in rule spec.tasks[].appTags.appType - MUST TAKE ALL THE TASKS APPTYPE AND REMOVE DUPLICATES - CRITICAL: DO NOT SKIP ANY TASK APPTYPES
        - Match ALL task appTypes with applications app_type to get application_class_name
        - Call check_applications_publish_status() for ALL matched applications

        2. Present consolidated applications with meaningful format
        Applications for your rule:
        [1] App Name | Type: xyz | Status: Published | Action: Republish
        [2] App Name | Type: abc | Status: Not Published | Action: Publish
        
        Select applications to publish: ___
        - MANDATORY: WAIT for user selection before proceeding to next step
        - DO NOT CONTINUE without explicit user input
        - BLOCK execution until user provides selection
        - STOP HERE: Cannot proceed to step 3 without user response
        - HALT WORKFLOW: Wait for user to select application numbers
        - NEVER SKIP THIS STEP: User must select applications first
        - ALWAYS ASK FOR SELECTION EVEN IF ALL APPLICATIONS ARE PUBLISHED

        3. Publish selected applications (BLOCKED until step 2 complete)
        - ENTRY REQUIREMENT: User selection from step 2 must be provided
        - PREREQUISITE CHECK: Verify user provided application numbers
        - CANNOT EXECUTE: Without completing step 2 user selection
        - Get user selection numbers
        - Call publish_application() for selected applications only
        - Inform user whether successfully published or not
        - CHECKPOINT: All applications must be published before rule steps

        4. Check rule publication status (APPLICATIONS MUST BE COMPLETE FIRST)
        - GATE KEEPER: Cannot proceed without application publishing completion
        - MANDATORY PREREQUISITE: All application steps finished
        - BLOCKED ACCESS: No rule operations until applications handled
        - Call check_rule_publish_status()
        - Check response valid field:
            - True = Already published
            - False = Not published

        5. Handle rule publishing based on status
        If valid=False (not published):
        - Show: "Rule is not published. Do you want to publish it? (yes/no)"
        - If yes: Proceed with publishing using current name
        
        If valid=True (already published):
        - Show: "Rule is already published. Choose option:"
            - [1] Republish with same name
            - [2] Publish with another name
        - Get user choice

        6. Handle alternative name logic
        If "another name" chosen:
            1. Ask: "Enter new rule name: ___"
            2. Call check_rule_publish_status(new_name)
            3. If name exists: "Name already exists. Choose option:"
                - [1] Use same name (republish)
                - [2] Enter another name
            4. If name available: Proceed with new name
            5. Keep checking until user chooses available name or decides to republish existing

        7. Final publication
        - Call publish_rule() with confirmed name
        - Inform user: "Published successfully" or "Publication failed"

        8. Rule Association:
            - Publishes the rule to make it available for control attachment
            - Ask user: "Do you want to attach this rule to a ComplianceCow control? (yes/no)"
            - If yes: Proceed to associate the rule with control and request assessment name and control alias from the user
            - If no: End workflow

        EXECUTION CONTROL MECHANISMS:
        - STEP GATE: Each step requires completion before next
        - USER GATE: Each step requires user input/confirmation
        - EXECUTION BLOCKER: No tool calls without user response
        - WORKFLOW ENFORCER: Steps cannot be skipped or assumed
        - SEQUENTIAL LOCK: Must complete in exact order

        Args:
            rule_name: Name of the rule to publish
            cc_rule_name: Optional alternative name for publishing
            
        Returns:
            Dict with publication status and details
        """
        try:
            headers = wsutils.create_header(ctx)
            
            # Prepare request data
            request_data = {
                "ruleName": rule_name
            }
            
            # Add ccRuleName only if provided
            if cc_rule_name:
                request_data["ccRuleName"] = cc_rule_name
            
            publish_resp = wsutils.post(
                path=wsutils.build_api_url(endpoint=constants.URL_PUBLISH_RULE),
                data=json.dumps(request_data),
                header=headers
            )

            base_host = constants.host.rstrip("/api") if hasattr(constants, "host") and isinstance(constants.host, str) else getattr(constants, "host", "")
            ui_url = f"{base_host}/ui/rules-workflow" if base_host else ""

            logger.debug(f"publish_rule: publish_resp: {publish_resp}\n")

            if publish_resp and publish_resp.get("message") and  publish_resp.get("message") == "Rule has been published successfully":
                resp = {
                    "success": True,
                    "published": True,
                    "rule_info": publish_resp.get("items"),
                    "message": f"Rule '{rule_name}' published successfully",
                    "ui_display_message": f"View your published rule on the ComplianceCow Rules Dashboard → {ui_url}"
                }

                if publish_resp.get("ruleId"):
                    resp["cc_rule_id"] = publish_resp.get("ruleId")
            
                return resp
            else:
                return {
                    "success": False,
                    "published": False,
                    "error": f"Rule '{rule_name}' failed to publish: {publish_resp}",
                    "rule_info": []
                }

        except Exception as e:
            return {
                "success": False,
                "published": False,
                "error": f"Failed to publish rule: {str(e)}",
                "rule_info": []
            }

    @mcp.tool()
    def verify_control_in_assessment(assessment_name: str, control_alias: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Verify the existence of a specific control by alias within an assessment and confirm it is a leaf control.

        CONTROL VERIFICATION AND VALIDATION:
        - Confirms the control with the specified alias exists in the given assessment.
        - Validates that the control is a leaf control (eligible for rule attachment).
        - Checks if a rule is already attached to the control.
        - Returns control details and attachment status.

        LEAF CONTROL IDENTIFICATION:
        - A control is considered a leaf control if:
        - leafControl = true, OR
        - has no planControls array, OR
        - planControls array is empty.
        - Only leaf controls can have rules attached.
        - If the control is not a leaf control, an error will be returned.

        Args:
            assessment_name: Name of the assessment.
            control_alias: Alias of the control to verify.

        Returns:
            Dict containing control details, leaf status, and rule attachment info.
        """
    
        try:

            assessment_params = {
                "fields": "basic",
                "skip_prereq_ctrl_priv_check": "false",
                "name": assessment_name,
                "is_leaf_control":True
            }
            
            assessments = rule.get_assessments(assessment_params)
            logger.debug("assessment_output_for_control_checking: {}\n".format(assessments))

            if len(assessments) == 0:
                return {"error":f"The requested assessment named {assessment_name} was not found."}
            
            assessment = assessments[0]

            control_params = {
                "fields": "basic",
                "skip_prereq_ctrl_priv_check": "false",
                "page_size": 500,
                "plan_id": assessment.id,
                "is_leaf_control":True
            }

            leaf_controls = rule.get_assessment_controls(control_params, ctx)

            if not leaf_controls or not isinstance(leaf_controls, list):
                return {"error": f"No leaf controls found for assessment '{assessment_name}'."}
            logger.debug(f"leaf_controls_output: {leaf_controls}\n")

            for control in leaf_controls:
                if str(control.alias) == control_alias:
                    if control.ruleId:
                        return {
                            "success": True,
                            "assessment_name": assessment_name,
                            "control_alias": control_alias,
                            "control_info": control,
                            "warning": f"Control '{control_alias}' already has a rule attached (Rule ID: {control.ruleId})",
                            "message": f"Control found but already has rule attached. Options: 1) View existing rule details, 2) Override with new rule attachment",
                            "next_actions": ["view_existing_rule", "override_attachment", "cancel"]
                        }

                    return {
                        "success": True,
                        "assessment_name": assessment_name,
                        "control_alias": control_alias,
                        "control_info": control,
                        "message": f"Leaf control '{control_alias}' found and available for rule attachment.",
                        "ready_for_attachment": True
                    }
                
            return {
                "success": False,
                "assessment_name": assessment_name,
                "control_alias": control_alias,
                "control_info": control,
                "error": f"Control alias '{control_alias}' was not found as a leaf control in assessment '{assessment_name}'.",
                "message": f"The control alias '{control_alias}' is either not present or is not a leaf control in the specified assessment '{assessment_name}'. Please make sure you provide a valid, available leaf control alias.",
                "next_actions": ["retry_with_valid_leaf_control", "cancel"]
            }
                    
        except Exception as e:
            return {
                "success": False,
                "assessment_name": assessment_name,
                "control_alias": control_alias,
                "error": f"Failed to find control: {str(e)}",
                "message": f"Error occurred while searching for the control **'{control_alias}'** in assessment **'{assessment_name}'**."
            }

    @mcp.tool()
    def publish_application(rule_name: str, app_info: list[dict], ctx: Context | None = None) -> dict[str, Any]:
        """
        Publish applications to make them available for rule execution.
        
        Args:
            rule_name: Name of the rule these applications belong to
            app_info: List of application objects to publish
            
        Returns:
            Dict with publication results for each application
        """
        try:
            headers = wsutils.create_header(ctx)
            
            # Prepare request data
            request_data = {
                "ruleName": rule_name,
                "appDetails": app_info
            }
            
            publish_resp = wsutils.post(
                path=wsutils.build_api_url(endpoint=constants.URL_PUBLISH_APPLICATIONS),
                data=json.dumps(request_data),
                header=headers
            )

            if publish_resp and len(publish_resp) > 0:
                # Separate successful and failed applications
                successful_apps = [app for app in publish_resp if "Error" not in app]
                failed_apps = [app for app in publish_resp if "Error" in app]
                
                if failed_apps:
                    failed_app_names = [app.get("appName", "Unknown") for app in failed_apps]
                    return {
                        "success": False,
                        "published": False,
                        "error": f"Failed applications: {', '.join(failed_app_names)}",
                        "successful_apps": successful_apps,
                        "failed_apps": failed_apps,
                        "message": f"Some applications failed to publish for rule '{rule_name}'"
                    }
                else:
                    return {
                        "success": True,
                        "published": True,
                        "successful_apps": successful_apps,
                        "failed_apps": [],
                        "message": f"All applications for rule '{rule_name}' published successfully"
                    }
            else:
                return {
                    "success": False,
                    "published": False,
                    "error": "No response received from publish endpoint",
                    "successful_apps": [],
                    "failed_apps": []
                }

        except Exception as e:
            return {
                "success": False,
                "published": False,
                "error": f"Failed to publish applications: {e}",
                "successful_apps": [],
                "failed_apps": []
            }

    # @mcp.prompt()
    def rule_input_collection():
        return """
        # RULE CREATION WITH MANDATORY TASK EXECUTION

        ## Core Principle
        **Every task MUST be executed immediately after collecting its inputs, before moving to the next task.**

        ## Workflow for Each Task (Sequential Order)

        ### Step 1: Collect Inputs
        - Collect ALL required inputs for the current task
        - Use `collect_template_input()` for files/templates
        - Use `collect_parameter_input()` for parameters
        - Confirm each input with user

        ### Step 2: Configure Application (If Needed)
        **Check task's appType:**
        - If `appType = "nocredapp"` → Skip to Step 3
        - If `appType ≠ "nocredapp"` → Application REQUIRED:
        1. Call `get_applications_for_tag(appType)`
        2. Show user: existing applications OR configure new credentials
        3. User selects option
        4. Collect and confirm application config
        5. **Cannot proceed without application**

        ### Step 3: Execute Task (MANDATORY - CANNOT SKIP)
        **⛔ This step is REQUIRED before moving to next task:**
        1. Call `execute_task(task_name, inputs, application)`
        2. Call `fetch_execution_progress()` - show live progress
        3. Display ALL output files to user
        4. Store output file URLs for next task

        **If execution fails:**
        - Show errors to user
        - Let user correct inputs
        - Re-execute until successful

        ### Step 4: Proceed to Next Task
        - Use REAL outputs from executed task
        - Start Step 1 for next task

        ## Quick Check Before Next Task
        Ask yourself:
        - ✅ Did I execute the current task?
        - ✅ Did I show the output files to user?
        - ✅ Do I have the output URLs?

        **If NO to any → STOP and complete that step first**

        ## What NOT to Do ❌
        - ❌ Collect inputs for Task 2 before executing Task 1
        - ❌ Skip execution to "save time"
        - ❌ Say "we'll execute later"
        - ❌ Use dummy data instead of real execution
        - ❌ Skip application config for non-nocredapp tasks

        ## Correct Pattern ✅
        ```
        Task 1: Collect inputs → Configure app (if needed) → Execute → Show results
        Task 2: Collect inputs → Configure app (if needed) → Execute → Show results  
        Task 3: Collect inputs → Configure app (if needed) → Execute → Show results
        Complete rule
        ```

        ## Wrong Pattern ❌
        ```
        Task 1: Collect inputs
        Task 2: Collect inputs
        Task 3: Collect inputs
        [Try to execute all later] ← WRONG!
        ```

        ## Remember
        Think of it as a pipeline: water must flow through valve 1 before you can open valve 2.
        **Execution is not optional. It happens NOW, not later.**
        """

    @mcp.tool()
    async def add_check_to_asset(assetId: str, parentControlId: str, checkName: str, checkDescription: str, ctx: Context | None = None) -> dict:
        """
            Add a new control and a new check to an asset under a specified parent control.
            The check will be attached to newly created control beneath the parent control.

            Args:
                - assetId (str): Asset id.
                - parentControlId (str): Parent control id under which the check will be added. 
                - checkName (str): Name of the check to be added.
                - checkDescription (str): Description of the check to be added.
            
            Returns:
                - success (bool): Indicates if the check was added successfully.
                - error (Optional[str]): An error message if any issues occurred during the addition. 
        """
        try:
            logger.info("add_check_to_asset: assetId: {}, parentControlId: {}, checkName: {}\n".format(assetId, parentControlId, checkName))
            
            payload={
                "assetID": assetId,
                "parentControlID": parentControlId,
                "checkName": checkName,
                "checkDescription": checkDescription
            }
            output = await utils.make_API_call_to_CCow_and_get_response(constants.URL_PLAN_CONTROLS+"/add-control-and-check", "POST", payload, ctx=ctx)
            logger.debug("add_check_to_asset output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))
            

            if isinstance(output, str):
                logger.error("add_check_to_asset error: {}\n".format(output))
                return {"success": False, "error": output}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("add_check_to_asset error: {}\n".format(output))
                    return {"success": False, "error": output}
                
                if "error" in output:
                    logger.error("add_check_to_asset error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error")}
            
            controlId = output.get("id","")

            return {"success": True, "controlId": controlId}
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("add_check_to_asset error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error adding check to asset: {e}"}


    @mcp.tool()
    async def create_asset_and_check(assetName: str, controlName: str, checkName: str, checkDescription: str, ctx: Context | None = None) -> dict:
        """
            Create a new asse with an initial control and check structure.
            The asset will be created with a hierarchical structure: asset -> parentcontrol -> control -> check.

            Args:
                - assetName (str): Name of the asset to be created.
                - controlName (str): Name of the initial control to be created within the asset.
                - checkName (str): Name of the initial check to be created under the control. (letters and numbers only, no spaces)
                - checkDescription (str): Description of the initial check.
            
            Returns:
                - success (bool): Indicates if the asset was created successfully.
                - assetId (str): ID of the created asset (only present if successful).
                - error (Optional[str]): An error message if any issues occurred during creation. 
        """
        try:
            logger.info("create_asset: assetName: {}, controlName: {}, checkName: {}\n".format(assetName, controlName, checkName))

            pattern = r"^[A-Za-z0-9]+$"
            match = re.search(pattern, checkName)
            if not match:
                return {"success": False, "error": "check name should match regex `^[A-Za-z0-9]+$`"}

            payload = {
                "name": assetName,
                "categoryName":"Integrations",
                "type": "integration",
                "status": "active",
                "linkToDefaultCCFPlan": {},
                "planControls": [
                    {
                        "displayable": "1",
                        "alias": "1",
                        "name": controlName,
                        "description": "",
                        "planControls": [
                            {
                                "displayable": "1.1",
                                "alias": "1.1",
                                "name": checkDescription,
                                "description": checkDescription,
                                "evidences": [
                                    {
                                        "name": checkName,
                                        "fileName": checkName,
                                        "description": checkDescription,
                                        "userDefinedSynthesizerName": "rule_default_synthesizer_card"
                                    }
                                ]
                            }
                        ],
                    },
                ],
            }

            output = await utils.make_API_call_to_CCow_and_get_response(constants.URL_PLANS, "POST", payload, ctx=ctx)
            logger.debug("create_asset output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))

            # Handle error response
            if isinstance(output, str):
                logger.error("create_asset error: {}\n".format(output))
                return {"success": False, "error": output}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("create_asset error: {}\n".format(output))
                    return {"success": False, "error": output}
                
                if "error" in output:
                    logger.error("create_asset error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error")}

            asset_id = output.get("id", "") if isinstance(output, dict) else ""

            parent_control_id = ""
            control_id = ""
            check_id = ""

            if asset_id:
                assets_output = await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_PLANS}/{asset_id}", "GET", ctx=ctx)
                logger.debug("created asset details: {}\n".format(json.dumps(assets_output) if isinstance(assets_output, dict) else assets_output))
                
                # Handle error response for fetching asset details
                if isinstance(assets_output, str):
                    logger.error("create_asset error while fetching created asset details: {}\n".format(assets_output))
                elif isinstance(assets_output, dict):
                    if "Message" in assets_output or "error" in assets_output:
                        logger.error("create_asset error while fetching created asset details: {}\n".format(assets_output))
                    else:
                        plan_controls = assets_output.get("planControls", [])
                        if plan_controls:
                            parent_control = plan_controls[0]
                            parent_control_id = parent_control.get("id", "")

                            child_controls = parent_control.get("planControls", [])
                            if child_controls:
                                leaf_control = child_controls[0]
                                control_id = leaf_control.get("id", "")

                                evidences = leaf_control.get("evidences", [])
                                if evidences:
                                    check_id = evidences[0].get("id", "")

            response = {
                "success": True,
                "assetId": asset_id,
                "parentControlId": parent_control_id,
                "controlId": control_id,
                "checkId": check_id,
            }

            logger.debug("created response: {}\n".format(response))

            return {"success": True, "response": response}

        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("create_asset error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error creating asset: {e}"}


    @mcp.tool()
    async def schedule_asset_execution(assetId: str, runPrefixName: str, description: str, cronTab: str,controlPeriod: str,controlDuration: int, ctx: Context | None = None) -> dict:
        """
            Schedule automated execution for a asset.

            IMPORTANT WORKFLOW & SAFETY RULES:
            - **User inputs (runPrefixName, cronTab) are mandatory and cannot be bypassed or assumed.**
            - The `cronTab` string **MUST** be constructed explicitly from the user's schedule instructions
            (e.g., frequency, time-of-day, timezone). Never auto-generate it without user confirmation.
            - `controlPeriod` **MUST** be one of the supported values.
            - `controlDuration` **MUST** be a positive integer provided by the user.
            Args:
                - assetId (str): Id of the asset to be scheduled.
                - runPrefixName (str): Human-readable name/prefix for this scheduled run.
                - description (str): Description for the scheduled run.
                - cronTab (str): Full cron expression including timezone (e.g. `TZ=Asia/Calcutta 0 0 * * *`),
                explicitly provided/confirmed by the user. **Must not be assumed or defaulted.**
                - controlPeriod (str): Control period for the assessment run, type selected by the user.
                    Allowed values:
                        - DAY        → Last few days
                        - WEEK       → Last few weeks
                        - MONTH      → Last few months
                        - CAL_WEEK   → Last few calendar weeks
                        - CAL_MONTH  → Last few calendar months
                - controlDuration (int): Duration count for the selected control period 
            Returns:
                - success (bool): Indicates if the schedule was created successfully.
                - scheduleId (str): ID of the created schedule (only present if successful).
                - error (Optional[str]): An error message if any issues occurred during creation.
        """
        try:
            logger.info(
                "schedule_asset_execution: assetId: %s, runPrefixName: %s, cronTab: %s\n",
                assetId,
                runPrefixName,
                cronTab,
            )

            if not assetId or not str(assetId).strip():
                return {"success": False, "error": "assetId is mandatory and cannot be empty"}

            if not runPrefixName or not str(runPrefixName).strip():
                return {
                    "success": False,
                    "error": "runPrefixName is mandatory and must be explicitly provided by the user",
                }

            if not description or not str(description).strip():
                return {
                    "success": False,
                    "error": "description is mandatory and must be explicitly provided by the user",
                }

            if not cronTab or not str(cronTab).strip():
                return {
                    "success": False,
                    "error": "cronTab is mandatory and must be explicitly constructed from the user's schedule",
                }

            # appScopeId = ""
            # appScopeName = ""

            # try:
            #     plan_resp = await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_PLANS}/{assetId}?fields=basic","GET",ctx=ctx)

            #     logger.debug(
            #             "plan_resp output: %s\n",
            #             json.dumps(plan_resp) if isinstance(plan_resp, dict) else plan_resp,
            #         )
            #     config_id = (
            #         plan_resp.get("configId")
            #         if isinstance(plan_resp, dict)
            #         else None
            #     )

            #     if config_id:
            #         appScopeId = config_id

            #         config_resp = await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_CONFIGURATION}?id={config_id}","GET",ctx=ctx)

            #         logger.debug(
            #             "config_resp output: %s\n",
            #             json.dumps(config_resp) if isinstance(config_resp, dict) else config_resp,
            #         )

            #         if (isinstance(config_resp, dict) and config_resp.get("items") and isinstance(config_resp["items"], list)):
            #             appScopeName = (
            #                 config_resp["items"][0].get("name", "")
            #             )

            # except Exception:
            #     logger.warning(
            #         "Unable to resolve appScopeId/appScopeName, continuing with empty values"
            #     )


            payload = {
                "name": str(runPrefixName).strip(),
                "description": str(description).strip(),
                "assessmentId": str(assetId).strip(),
                "appScopeId": None,
                "appScopeName": "",
                # "appScopeId": appScopeId,
                # "appScopeName": appScopeName,
                "useDefaultConfig": True,
                "controlPeriod": {
                    "schema": 1,
                    "period": controlPeriod,
                    "duration": controlDuration,
                },
                "cronTab": str(cronTab).strip(),
                "status": "ACTIVE",
                "tag": {},
            }

            logger.debug(
                "schedule_asset_execution payload: %s\n", json.dumps(payload)
            )

            output = await utils.make_API_call_to_CCow_and_get_response(
                constants.URL_ASSESSMENT_SCHEDULE, "POST", payload, ctx=ctx
            )
            logger.debug(
                "schedule_asset_execution output: %s\n",
                json.dumps(output) if isinstance(output, dict) else output,
            )

            if isinstance(output, str):
                logger.error("schedule_asset_execution error: %s\n", output)
                return {"success": False, "error": output}

            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("schedule_asset_execution error: %s\n", output)
                    return {"success": False, "error": output}

                if "error" in output:
                    logger.error(
                        "schedule_asset_execution error: %s\n", output.get("error")
                    )
                    return {"success": False, "error": output.get("error")}

            schedule_id = output.get("id", "") if isinstance(output, dict) else ""

            return {
                "success": True,
                "scheduleId": schedule_id,
            }

        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("schedule_asset_execution error: %s\n", e)
            return {
                "success": False,
                "error": f"Unexpected error scheduling asset execution: {e}",
            }

    @mcp.tool()
    async def delete_asset_schedule( scheduleId: str, ctx: Context | None = None) -> dict:
        """
        Delete an existing assessment schedule.

        Args:
            - scheduleId (str): ID of the schedule to delete

        Returns:
            - success (bool)
            - error (Optional[str])
        """
        try:
            logger.info("delete_asset_schedule: scheduleId: %s", scheduleId)

            if not scheduleId or not str(scheduleId).strip():
                return {
                    "success": False,
                    "error": "scheduleId is mandatory and cannot be empty",
                }

            url = f"{constants.URL_ASSESSMENT_SCHEDULE}/{str(scheduleId).strip()}"

            output = await utils.make_API_call_to_CCow_and_get_response( url, "DELETE", ctx=ctx)

            logger.debug(
                "delete_asset_schedule output: %s",
                json.dumps(output) if isinstance(output, dict) else output,
            )

            if isinstance(output, str):
                return {"success": False, "error": output}

            if isinstance(output, dict):
                if "Message" in output:
                    return {"success": False, "error": output}

                if "error" in output:
                    return {"success": False, "error": output.get("error")}

            return {
                "success": True
            }

        except Exception as e:
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "error": f"Unexpected error deleting schedule: {e}",
            }

    @mcp.tool()
    async def suggest_control_citations(
        controlName: str,
        description: str,
        controlId: str = "",
        ctx: Context | None = None
    ) -> dict:
        """
        Suggest control citations for a given control name or description.
        
        WORKFLOW: When user provides a requirement, ask which assessment they want to use.
        Get assessment name from user, then resolve to assessmentId (mandatory).
        For control: offer two options - select from existing control on selected assessment OR create new control.
        If selecting existing control, get control name from user and resolve to controlId.
        If creating new control, controlId will be empty.
        
        This function provides suggestions for control citations based on control names or descriptions.
        The user can select from the suggested controls to attach citations to their assessment controls.
        
        Args:
            controlName (str): Name of control to get suggestions for (required).
            assessmentId (str): Assessment ID - resolved from assessment name (required).
            description (str, optional): Description of the control to get suggestions for.
            controlId (str, optional): Control ID - resolved from control name if selecting existing control, empty if creating new control.
        
        Returns:
            Dict with success status and suggestions:
            - success (bool): Whether the request was successful
            - items (list[dict]): list of suggestion items, each containing:
                - inputControlName (str): The input control name
                - controlId (str): The control ID (empty if control doesn't exist yet)
                - suggestions (list[dict]): list of suggested controls, each containing:
                    - Name (str): Control name
                    - Control ID (int): Control ID number
                    - Control Classification (str): Classification type
                    - Impact Zone (str): Impact zone category
                    - Control Requirement (str): Requirement level
                    - Sort ID (str): Sort identifier
                    - Control Type (str): Type of control
                    - Score (float): Similarity score
            - authorityDocument (str): Name of the authorityDocument
            - error (str, optional): Error message if request failed
        """
        try:
            logger.info("suggest_control_config_citations: \n")

            if not controlName or not str(controlName).strip():
                logger.error("suggest_control_config_citations error: control name is mandatory and cannot be empty\n")
                return {"success": False, "error": "control name is mandatory and cannot be empty"}
            
            payload = {
                "assessment_type": "asset",
                "assessment_id": "",
                "assessment_name": "",
                "use_default_authority_document": True,
                "controls": [
                    {
                        "id": "",
                        "name": str(controlName).strip(),
                        "description": str(description).strip() if description else ""
                    }
                ]
            }
            
            logger.debug("suggest_control_config_citations payload: {}\n".format(json.dumps(payload)))
            
            resp = await utils.make_API_call_to_CCow(payload, constants.URL_GET_SIMILAR_CONTROLS, ctx=ctx)
            logger.debug("suggest_control_config_citations output: {}\n".format(json.dumps(resp) if isinstance(resp, dict) else resp))
            
            if isinstance(resp, str):
                logger.error("suggest_control_config_citations error: {}\n".format(resp))
                return {"success": False, "error": resp}
            
            if isinstance(resp, dict):
                if "error" in resp:
                    logger.error("suggest_control_config_citations error: {}\n".format(resp.get("error")))
                    return {"success": False, "error": resp.get("error")}
                
                if "Message" in resp:
                    logger.error("suggest_control_config_citations error: {}\n".format(resp))
                    return {"success": False, "error": resp}
                
                items = resp.get("items", [])
                authorityDocument = resp.get("authorityDocument", "")
                abstracted_items = []
                for item in items:
                    if isinstance(item, dict):
                        abstracted_item = {
                            "inputControlName": item.get("inputControlName", ""),
                            "controlId": item.get("controlId", ""),
                            "suggestions": []
                        }
                        suggestions = item.get("suggestions", [])
                        for suggestion in suggestions:
                            if isinstance(suggestion, dict):
                                abstracted_suggestion = {
                                    "Name": suggestion.get("Name", ""),
                                    "Control ID": suggestion.get("Control ID", ""),
                                    "Control Classification": suggestion.get("Control Classification", ""),
                                    "Impact Zone": suggestion.get("Impact Zone", ""),
                                    "Control Requirement": suggestion.get("Control Requirement", ""),
                                    "Sort ID": suggestion.get("Sort ID", ""),
                                    "Control Type": suggestion.get("Control Type", ""),
                                    "Score": suggestion.get("Score", 0.0)
                                }
                                abstracted_item["suggestions"].append(abstracted_suggestion)
                        abstracted_items.append(abstracted_item)
                
                logger.info(f"suggest_control_config_citations: Successfully retrieved {len(abstracted_items)} suggestion item(s)\n")
                return {"success": True, "items": abstracted_items,"authorityDocument": authorityDocument, "next_action": "attachToControl"}
            
            logger.error("suggest_control_config_citations error: Unexpected response type: {}\n".format(type(resp)))
            return {"success": False, "error": f"Unexpected response type: {resp}"}
            
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("suggest_control_config_citations error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error suggesting control citations: {e}"}


    @mcp.tool()
    async def add_citation_to_asset_control(assetControlId: str, authorityDocument: str, authorityDocumentControlId: str, ctx: Context | None = None) -> dict:
        """
            Create a new asse with an initial control and check structure.
            The asset will be created with a hierarchical structure: asset -> control -> check.
        
            Args:
                - assetControlId (str): Id of the control in asset.
                - authorityDocument (str): Authority document name of the citation.
                - authorityDocumentControlId (str): Id of the control in authority document.
            
            Returns:
                - success (bool): Indicates if the citation was created successfully.
                - error (Optional[str]): An error message if any issues occurred during creation. 
        """
        try:
            logger.info("add_citation_to_asset_control: assetControlId: {}, authorityDocument: {}, authorityDocumentControlId: {}\n".format(assetControlId, authorityDocument, authorityDocumentControlId))

            payload = {
                "citation": {
                    "authorityDocument": authorityDocument,
                    "controlsInAuthorityDocument": [authorityDocumentControlId]
                }
            }
            output = await utils.make_API_call_to_CCow_and_get_response(constants.URL_PLAN_CONTROLS+"/"+assetControlId+"/link-source-control", "POST", payload, ctx=ctx)
            logger.debug("add_citation_to_asset_control output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))

            if isinstance(output, str):
                logger.error("add_citation_to_asset_control error: {}\n".format(output))
                return {"success": False, "error": output}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("add_citation_to_asset_control error: {}\n".format(output))
                    return {"success": False, "error": output}
                
                if "error" in output:
                    logger.error("add_citation_to_asset_control error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error")}

            return {"success": True}

        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("add_citation_to_asset_control error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error adding citation to asset control: {e}"}

    @mcp.tool()
    async def create_control_note(
        controlId: str,
        assessmentId: str,
        notes: str,
        topic: str,
        confirm: bool = False,
        ctx: Context | None = None,
    ) -> dict:
        """
        Create a documentation note on a control.
        
        This tool creates a markdown documentation note that is attached to a control.
        
        ✅ CONFIRMATION-BASED SAFETY FLOW
        - When confirm=False:
            → The tool returns a PREVIEW of the generated markdown note.
            → The user may edit the note before confirming.
        - When confirm=True:
            → The note is permanently created and attached to the control.
        
        Args:
            controlId (str): The control ID where the note will be attached (required).
            assessmentId (str): The assessment ID or asset ID that contains the control (required).
            notes (str): The documentation content in MARKDOWN format (required).
            topic (str, optional): Topic or subject of the note.
            confirm (bool, optional):  
                - False → Preview only (default, no persistence)
                - True  → Create and permanently attach the note
        
        Returns:
            Dict with success status and note data:
            - success (bool): Whether the request was successful
            - note (dict, optional): Created note object containing:
                - id (str): Note ID
                - topic (str): Note topic
                - notes (str): Note content in markdown format
                - controlId (str): Control ID the note is attached to
                - assessmentId (str): Assessment ID
            - error (str, optional): Error message if request failed
            - next_action (str, optional): Recommended next action
        """
        try:
            logger.info("create_control_note: \n")
            
            if not controlId or not str(controlId).strip():
                logger.error("create_control_config_note error: controlId is mandatory\n")
                return {"success": False, "error": "controlId is mandatory"}
            
            if not assessmentId or not str(assessmentId).strip():
                logger.error("create_control_config_note error: assessmentId is mandatory\n")
                return {"success": False, "error": "assessmentId is mandatory"}
            
            if not notes or not str(notes).strip():
                logger.error("create_control_config_note error: notes content is mandatory\n")
                return {"success": False, "error": "notes content is mandatory"}
            
            # Build payload
            payload = {
                "topic": str(topic).strip(),
                "notes": str(notes).strip(),
                "planId": str(assessmentId).strip(),
                "planControlID": str(controlId).strip(),
            }

            if not confirm:
                logger.info("create_control_config_note: Returning confirmation preview\n")
                return {
                    "success": True,
                    "message": "Confirmation required before creating note",
                    "controlId": payload["planControlID"],
                    "topic": payload["topic"],
                    "notes": payload["notes"],
                    "next_step": "Review the Note above. If you need to modify it, provide the updated note parameter when calling with confirm=True. If correct, re-run with confirm=True to create note."
            }
            
            # Construct URL with control ID
            url = constants.URL_PLAN_CONTROL_NOTES.format(controlConfigId=str(controlId).strip())
            
            logger.debug("create_control_note payload: {}\n".format(json.dumps(payload)))
            logger.debug("create_control_note URL: {}\n".format(url))
            
            # Make API call
            resp_raw = await utils.make_API_call_to_CCow_and_get_response(
                url,
                "POST",
                payload,
                return_raw=True,
                ctx=ctx
            )

            if resp_raw.status_code == 502:
                return {"success": False, "error": error_constants.ERROR_BAD_GATEWAY}
            
            
            if resp_raw.status_code == 201:
                resp = {}
                try:
                    if resp_raw.content:
                        resp = resp_raw.json()
                except Exception:
                    resp = {"error": f"HTTP {resp_raw.status_code}"}

                logger.info(f"create_control_note: \n Response : {resp}\n")
                noteId = ""
                if isinstance(resp, dict):
                    noteId = resp.get("id")
                
                logger.info(f"create_control_note: Successfully created note with status 201\n")
                return {
                    "success": True,
                    "noteId": noteId,
                    "message": "Note created successfully",
                }
            else:
                # Error - parse error response
                error_resp = {}
                try:
                    if resp_raw.content:
                        error_resp = resp_raw.json()
                except Exception:
                    error_resp = {"error": f"HTTP {resp_raw.status_code}"}
                
                logger.error("create_control_note error: Status {} - {}\n".format(resp_raw.status_code, error_resp))
                
                # Check for error fields in response
                if isinstance(error_resp, dict):
                    if "Message" in error_resp:
                        return {"success": False, "error": error_resp}
                    if "error" in error_resp:
                        return {"success": False, "error": error_resp.get("error")}

                return {"success": False, "error": f"Failed to create note: HTTP {resp_raw.status_code}"}
            
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("create_control_note error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error creating control note: {e}"}

    @mcp.tool()
    async def update_control_note(
        controlId: str,
        noteId: str,
        assessmentId: str,
        notes: str,
        topic: str,
        confirm: bool = False,
        ctx: Context | None = None,
    ) -> dict:
        """
        Update an existing documentation note on a control.
        
        ✅ PURPOSE
        This tool updates an existing note that was previously created on a control.
        It allows modification of the note content, topic, or both.
        
        ✅ CONFIRMATION-BASED SAFETY FLOW
        - When confirm=False:
            → The tool returns a PREVIEW of the updated markdown note.
            → The user may edit the note before confirming.
        - When confirm=True:
            → The note is permanently updated and saved.
        
        Args:
            controlId (str): The control ID where the note exists (required).
            noteId (str): The note ID to update (required).
            assessmentId (str): The assessment ID or asset ID that contains the control (required).
            notes (str): The updated documentation content in MARKDOWN format (required).
            topic (str, optional): Updated topic or subject of the note.
            confirm (bool, optional):  
                - False → Preview only (default, no persistence)
                - True  → Update and permanently save the note
        
        Returns:
            Dict with success status and note data:
            - success (bool): Whether the request was successful
            - message (str, optional): Success or error message
            - noteId (str, optional): Updated note ID
            - error (str, optional): Error message if request failed
        """
        try:
            logger.info("update_control_config_note: \n")
            
            if not controlId or not str(controlId).strip():
                logger.error("update_control_config_note error: controlId is mandatory\n")
                return {"success": False, "error": "controlId is mandatory"}
            
            if not noteId or not str(noteId).strip():
                logger.error("update_control_config_note error: noteId is mandatory\n")
                return {"success": False, "error": "noteId is mandatory"}
            
            if not assessmentId or not str(assessmentId).strip():
                logger.error("update_control_config_note error: assessmentId is mandatory\n")
                return {"success": False, "error": "assessmentId is mandatory"}
            
            if not notes or not str(notes).strip():
                logger.error("update_control_config_note error: notes content is mandatory\n")
                return {"success": False, "error": "notes content is mandatory"}
            
            # Build payload
            payload = {
                "topic": str(topic).strip(),
                "notes": str(notes).strip(),
                "planId": str(assessmentId).strip(),
                "planControlID": str(controlId).strip(),
            }

            if not confirm:
                logger.info("update_control_config_note: Returning confirmation preview\n")
                return {
                    "success": True,
                    "message": "Confirmation required before updating note",
                    "controlId": payload["planControlID"],
                    "noteId": str(noteId).strip(),
                    "topic": payload["topic"],
                    "notes": payload["notes"],
                    "next_step": "Review the updated Note above. If you need to modify it, provide the updated notes or topic parameters when calling with confirm=True. If correct, re-run with confirm=True to update the note."
                }
            
            # Construct URL with control ID and note ID
            url = f"{constants.URL_PLAN_CONTROL_NOTES.format(controlConfigId=str(controlId).strip())}/{str(noteId).strip()}"
            
            logger.debug("update_control_config_note payload: {}\n".format(json.dumps(payload)))
            logger.debug("update_control_config_note URL: {}\n".format(url))
            
            # Make API call
            resp_raw = await utils.make_API_call_to_CCow_and_get_response(
                url,
                "PUT",
                payload,
                return_raw=True,
                ctx=ctx
            )

            if resp_raw.status_code == 502:
                return {"success": False, "error": error_constants.ERROR_BAD_GATEWAY}
            
            if resp_raw.status_code == 204:
                logger.info(f"update_control_config_note: Successfully updated note with status 204\n")
                return {
                    "success": True,
                    "noteId": str(noteId).strip(),
                    "message": "Note updated successfully",
                }
            else:
                # Error - parse error response
                error_resp = {}
                try:
                    if resp_raw.content:
                        error_resp = resp_raw.json()
                except Exception:
                    error_resp = {"error": f"HTTP {resp_raw.status_code}"}
                
                logger.error("update_control_config_note error: Status {} - {}\n".format(resp_raw.status_code, error_resp))
                
                # Check for error fields in response
                if isinstance(error_resp, dict):
                    if "Message" in error_resp:
                        return {"success": False, "error": error_resp}
                    if "error" in error_resp:
                        return {"success": False, "error": error_resp.get("error")}

                return {"success": False, "error": f"Failed to update note: HTTP {resp_raw.status_code}"}
            
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("update_control_config_note error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error updating control note: {e}"}


@mcp.tool()
def collect_template_input(task_name: str, input_name: str, user_content: Any, ctx: Context | None = None) -> dict[str, Any]:
    """Collect user input for template-based task inputs.

    TEMPLATE INPUT PROCESSING (Enhanced with Progressive Saving):
    - Validates user content against template format (JSON/TOML/YAML)
    - Handles JSON arrays and objects properly
    - Checks for required fields from template structure
    - Uploads validated content as file (ONLY for FILE dataType inputs)
    - Returns file URL for use in rule structure
    - MANDATORY: Gets final confirmation for EVERY input before proceeding
    - CRITICAL: Only processes user-provided content, never use default templates
    - NEW: Prepared for automatic rule updates in confirm step

    JSON ARRAY HANDLING (Preserved):
    - Properly validates JSON arrays: [{"key": "value"}, {"key": "value"}]
    - Validates JSON objects: {"key": "value", "nested": {"key": "value"}}
    - Handles complex nested structures with arrays and objects
    - Validates each array element and object property

    VALIDATION REQUIREMENTS (Preserved):
    - JSON: Must be valid JSON (arrays/objects) with proper brackets and quotes
    - TOML: Must follow TOML syntax with proper sections [section_name]
    - YAML: Must have correct indentation and structure
    - XML: Must be well-formed XML with proper tags
    - Required fields: All template fields must be present in user content

    STREAMLINED WORKFLOW:
    1. User provides template content
    2. Validate and process immediately
    3. Auto-proceed if validation passes

    FILE NAMING CONVENTION (Preserved):
    - Format: {task_name}_{input_name}.{extension}
    - Extensions: .json, .toml, .yaml, .xml, .txt based on format

    WORKFLOW INTEGRATION (Enhanced):
    1. Called after get_template_guidance() shows template to user
    2. User provides their actual configuration content
    3. This tool validates content (including JSON arrays)
    4. Shows content preview and asks for confirmation
    5. Only after confirmation: uploads file or stores in memory
    6. Returns file URL or memory reference for rule structure
    7. NEW: Prepared for rule update in confirm_template_input()

    CRITICAL RULES (Preserved):
    - ONLY upload files for inputs with dataType = "FILE" or "HTTP_CONFIG"
    - Template inputs and HTTP_CONFIG inputs are typically file types and need file uploads
    - Store non-FILE template content in memory
    - ALWAYS get final confirmation before proceeding
    - Handle JSON arrays properly: validate each element
    - Never use template defaults - always use user-provided content

    MANDATORY: Task-sequential collection only. Sanitize input names (alphanumeric + underscore).

    Args:
        task_name: Name of the task this input belongs to
        input_name: Name of the input parameter
        user_content: Content provided by the user based on the template

    Returns:
        Dict containing validation results and file URL or memory reference,
        prepared for progressive rule updates
    """
    try:
        task = None
        tasks_resp = rule.fetch_task_api(params={"name": task_name}, ctx=ctx)
        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            task = TaskVO.from_dict(tasks_resp["items"][0])
        if not task:
            return {"success": False, "error": f"Task '{task_name}' not found in available tasks"}

        # Find the specific input
        task_input = None
        available_task_inputs=[]
        for inp in task.inputs:
            if inp.name == input_name:
                available_task_inputs.append(inp.name)
                task_input = inp
                break

        if not task_input:
            return {"success": False, "error": f"Input '{input_name}' not found in task '{task_name}'. Available inputs are: {available_task_inputs}"}
        
        # Check type and convert to string
        if isinstance(user_content, (dict, list)):
            user_content = json.dumps(user_content)
        else:
            user_content = str(user_content)

        # Validate the content including JSON arrays (preserved validation)
        validation_result = rule.validate_template_content_enhanced(task_input, user_content)
        if not validation_result["valid"]:
            return {"success": False, "error": "Content validation failed", "validation_errors": validation_result["errors"], "suggestions": validation_result["suggestions"]}

        # Generate content preview for confirmation (preserved)
        content_preview = rule.generate_content_preview(user_content, task_input.format)

        # Need final confirmation before storing/uploading
        result =  {
            "success": True,
            "task_name": task_name,
            "input_name": input_name,
            "validated_content": user_content,
            "content_preview": content_preview,
            "needs_final_confirmation": True,
            "data_type": task_input.dataType,
            "format": task_input.format,
            "is_file_type": task_input.dataType.upper() in ["FILE", "HTTP_CONFIG"],
            "final_confirmation_message": f"You provided this {task_input.format.upper()} content:\n\n{content_preview}\n\nIs this correct? (yes/no)",
            "message": "Template content validated - needs final confirmation before processing and rule update",
            "ready_for_rule_update": True  # NEW: Indicates this input is ready for rule progression
        }

        return result

    except Exception as e:
        return {"success": False, "error": f"Failed to process template input: {e}"}


@mcp.tool()
def confirm_template_input(rule_name: str, task_name: str, rule_input_name: str, input_name: str, confirmed_content: str, ctx: Context | None = None) -> dict[str, Any]:
    """Confirm and process template input after user validation.

    CONFIRMATION PROCESSING (Enhanced with Automatic Rule Updates):
    - Handles final confirmation of template content
    - Uploads files for FILE dataType inputs
    - Stores content in memory for non-FILE inputs
    - MANDATORY step before proceeding to next input
    - NEW: Automatically updates the rule with new input after processing
    - Skips confirmation if the user accepts the suggested template

    PROCESSING RULES (Enhanced):
    - FILE dataType: Upload content as file, return file URL
    - HTTP_CONFIG dataType: Upload content as file, return file URL
    - Non-FILE dataType: Store content in memory
    - Include metadata about confirmation and timestamp
    - NEW: Automatic rule update with new input data

    AUTOMATIC RULE UPDATE PROCESS:
    After successful input processing, this tool automatically:
    1. Fetches the current rule structure
    2. Adds the new input to spec.inputs
    3. Updates spec.inputsMeta__ with input metadata
    4. Calls create_rule() to save the updated rule
    5. Rule status will be auto-detected (DRAFT → collecting_inputs → READY_FOR_CREATION)

    UI DISPLAY REQUIREMENT:
    - The file URL must ALWAYS be displayed to the user in the UI, allowing the user to view or download the file directly.
    
    Args:
        rule_name: Descriptive name for the rule based on the user's use case. 
                   Note: Use the same rule name for all inputs that belong to this rule.
                   Example: rule_name = "MeaningfulRuleName"
        task_name: Name of the task this input belongs to
        input_name: Name of the input parameter
        rule_input_name: Must be one of the values defined in the rule structure's inputs
        confirmed_content: The content user confirmed

    Returns:
        Dict containing processing results (file URL or memory reference) and rule update status
    """
    try:
        task = None
        tasks_resp = rule.fetch_task_api(params={"name": task_name}, ctx=ctx)
        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            task = TaskVO.from_dict(tasks_resp["items"][0])
        if not task:
            return {"success": False, "error": f"Task '{task_name}' not found in available tasks"}

        # Find the specific input
        task_input = None
        available_task_inputs=[]
        for inp in task.inputs:
            available_task_inputs.append(inp.name)
            if inp.name == input_name:
                task_input = inp
                break

        if not task_input:
            return {"success": False, "error": f"Input '{input_name}' not found in task '{task_name}'. Available inputs are: {available_task_inputs}"}

        # Check if this is a FILE or HTTP_CONFIG type input that needs upload (preserved logic)
        if task_input.dataType.upper() in ["FILE", "HTTP_CONFIG"]:
            # Generate appropriate filename
            file_extension = rule.get_file_extension(task_input.format)
            file_name = f"{task_name}_{input_name}{file_extension}"

            # Upload the file and get URL
            upload_result = upload_file(rule_name=rule_name, file_name=file_name, content=confirmed_content, ctx=ctx)

            if upload_result["success"]:
                input_value = upload_result["file_url"]
                storage_type = "FILE"
            else:
                return {"success": False, "error": f"File upload failed: {upload_result.get('error', 'Unknown error')}"}
        else:
            # For non-FILE inputs, store content in memory (don't upload)
            input_value = confirmed_content
            storage_type = "MEMORY"

        # NEW: AUTOMATIC RULE UPDATE WITH NEW INPUT
        rule_update_success = False
        rule_status = "UNKNOWN"
        rule_progress = 0
        
        try:
            # Fetch current rule
            current_rule = fetch_rule(rule_name, ctx)
            logger.info(f"current_rule ::{current_rule}")
            if current_rule["success"]:
                rule_structure = current_rule["rule_structure"]

                logger.info(f"rule_structure 111 ::{rule_structure}")

                if not rule.is_valid_key(rule_structure["spec"],"inputs"):
                    rule_structure["spec"]["inputs"] = {}
                
                # Add new input to rule structure
                rule_structure["spec"]["inputs"][rule_input_name] = input_value
                
                # Add/update input metadata
                input_meta = {
                    "name": rule_input_name,
                    "dataType": task_input.dataType,
                    "required": task_input.required,
                    "defaultValue": input_value
                }
                if hasattr(task_input, 'format') and task_input.format:
                    input_meta["format"] = task_input.format

                logger.info(f"rule_structure 2222 ::{rule_structure}")

                if not rule.is_valid_key(rule_structure["spec"],"inputsMeta__"):
                    rule_structure["spec"]["inputsMeta__"] = []
                
                # Remove existing metadata for this input and add new one
                existing_meta = rule_structure["spec"]["inputsMeta__"]
                rule_structure["spec"]["inputsMeta__"] = [m for m in existing_meta if m["name"] != rule_input_name]
                rule_structure["spec"]["inputsMeta__"].append(input_meta)


                logger.info(f"rule_structure 3333 ::{rule_structure}")
                
                # Update rule - status will be auto-detected
                update_result = create_rule(rule_structure, ctx)
                logger.info(f"update_result ::{update_result}")
                rule_update_success = update_result["success"]
                rule_status = update_result.get("detected_status", "UNKNOWN")
                rule_progress = update_result.get("progress_percentage", 0)
                
        except Exception as update_error:
            # Log the error but don't fail the input processing
            print(f"Warning: Rule update failed for {rule_name}: {update_error}")

        return {
            "success": True,
            "task_name": task_name,
            "input_name": input_name,
            "file_url": input_value if storage_type == "FILE" else None,
            "stored_content": input_value if storage_type == "MEMORY" else None,
            "filename": file_name if storage_type == "FILE" else None,
            "content_size": len(confirmed_content),
            "storage_type": storage_type,
            "data_type": task_input.dataType,
            "format": task_input.format,
            "timestamp": datetime.now().isoformat(),
            "rule_name": rule_name,
            "rule_updated": rule_update_success,
            "rule_status": rule_status,
            "rule_progress": rule_progress,
            "message": f"Template file {'uploaded' if storage_type == 'FILE' else 'stored'} successfully for {input_name} in {task_name}. Rule '{rule_name}' {'updated automatically' if rule_update_success else 'update failed'}."
        }

    except Exception as e:
        return {"success": False, "error": f"Failed to confirm template input: {e}"}


@mcp.tool()
def upload_file(rule_name: str, file_name: str, content: Any, content_encoding: str = "utf-8", ctx: Context | None = None) -> dict[str, Any]:
    """
    Upload file content and return file URL for use in rules.

    ENHANCED FILE UPLOAD PROCESS:
    - Automatically detects file format from filename and content
    - Validates and fixes common formatting issues for JSON, YAML, TOML, CSV, XML
    - Accepts JSON arrays in various formats: raw, single-line, multi-line, or escaped (auto-formatted).
    - Normalizes CSV delimiters and whitespace
    - Reformats content with proper indentation/structure
    - No user preview required - validation happens automatically
    - Returns detailed validation results and file URL

    SUPPORTED INPUT FORMATS:
    - Raw JSON: {"key": "value"} or [{"key": "value"}]
    - Escaped JSON: "{"key": "value"}" 
    - Complex escaped: "[{"repository":"name","owner":"org"}]"
    - Standard strings for other formats (YAML, TOML, CSV, XML)

    AUTOMATIC FORMAT PROCESSING:
    - JSON: Detects escaped strings, unescapes, validates syntax, reformats with indentation
    - Raw JSON objects/arrays: Automatically converts to proper JSON string format
    - YAML: Validates structure, reformats with proper indentation  
    - TOML: Validates sections and key-value pairs, reformats
    - CSV: Detects delimiter, strips cell whitespace, normalizes format
    - XML: Validates well-formed structure
    - Other formats: Pass through as-is

    VALIDATION RESULTS:
    - Returns success/failure status with detailed error messages
    - Provides format-specific validation feedback
    - Indicates if content was automatically reformatted
    - Includes file metadata (size, format, etc.)

    Args:
        rule_name: Descriptive name for the rule (same across all rule inputs)
        file_name: Name of the file to upload  
        content: File content (text or base64 encoded)
                 CRITICAL: Must be stringified if JSON content   
        content_encoding: Encoding of the content (utf-8, base64)

    Returns:
        Dict containing upload results: 
        {
            success: bool,
            file_url: str,
            filename: str,
            unique_filename: str,
            file_id: str,
            file_format: str,
            content_size: int,
            validation_status: str,
            was_formatted: bool,
            message: str,
            error: Optional[str]
        }
    """
    try:
        # Validate content encoding
        if content_encoding not in ["utf-8", "base64"]:
            return {
                "success": False,
                "error": f"Unsupported encoding: {content_encoding}",
                "filename": file_name,
                "supported_encodings": ["utf-8", "base64"]
            }

        # Check type and convert to string
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        else:
            content = str(content)

        # Decode content if base64
        if content_encoding == "base64":
            try:
                decoded_content = base64.b64decode(content).decode("utf-8")
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Failed to decode base64 content: {e}",
                    "filename": file_name
                }
        else:
            decoded_content = content

        # Auto-detect file format
        file_format = rule.detect_file_format(file_name, decoded_content)

        # Validate and format content automatically
        formatted_content, is_valid, validation_message = rule.validate_and_format_content(
            decoded_content, file_format)

        # If validation failed, return error with details
        if not is_valid:
            return {
                "success": False,
                "error": f"File validation failed: {validation_message}",
                "filename": file_name,
                "file_format": file_format,
                "suggestion": "Please check your file content and format, then try again"
            }

        # Convert formatted content to base64 for upload
        encoded_content = base64.b64encode(
            formatted_content.encode("utf-8")).decode("utf-8")

        # Generate file ID and unique filename
        file_id = f"file_{abs(hash(encoded_content)) % 100000}"
        unique_file_name = f"{file_id}_{file_name}"

        # Upload file using existing API
        headers = wsutils.create_header(ctx)
        payload = {
            "fileName": unique_file_name,
            "fileContent": encoded_content,
            "ruleName": rule_name
        }

        file_upload_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_UPLOAD_FILE),
            data=json.dumps(payload),
            header=headers
        )

        if rule.is_valid_key(file_upload_resp, "fileURL"):
            return {
                "success": True,
                "file_url": file_upload_resp["fileURL"],
                "filename": file_name,
                "unique_filename": unique_file_name,
                "file_id": file_id,
                "file_format": file_format,
                "content_size": len(formatted_content),
                "validation_status": validation_message,
                "was_formatted": formatted_content != decoded_content,
                "message": f"File '{file_name}' uploaded successfully with {file_format.upper()} validation"
            }

        return {
            "success": False,
            "error": "Upload API did not return file URL",
            "filename": file_name,
            "file_format": file_format
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Upload failed: {e}",
            "filename": file_name,
            "exception_type": type(e).__name__
        }


@mcp.tool()
def collect_parameter_input(task_name: str, input_name: str, user_value: str = None, use_default: bool = False, ctx: Context | None = None) -> dict[str, Any]:
    """Collect user input for non-template parameter inputs.

    PARAMETER INPUT PROCESSING:
    - Collects primitive data type values (STRING, INT, FLOAT, BOOLEAN, DATE, DATETIME)
    - Stores values in memory (NEVER uploads files for primitive types)
    - Handles optional vs required inputs based on 'required' attribute
    - Supports default value confirmation workflow
    - Validates data types and formats
    - MANDATORY: Gets final confirmation for EVERY input before proceeding

    INPUT REQUIREMENT RULES:
    - MANDATORY: Only if input.required = true
    - OPTIONAL: If input.required = false, user can skip or provide value
    - DEFAULT VALUES: If user requests defaults, must get confirmation
    - FINAL CONFIRMATION: Always required before proceeding to next input

    DEFAULT VALUE WORKFLOW:
    1. User requests to use default values
    2. Show default value to user for confirmation
    3. "I can fill this with the default value: '[default_value]'. Confirm?"
    4. Only proceed after explicit user confirmation
    5. Store confirmed default value in memory

    FINAL CONFIRMATION WORKFLOW (MANDATORY):
    1. After user provides value (or confirms default)
    2. Show final confirmation: "You entered: '[value]'. Is this correct? (yes/no)"
    3. If 'yes': Store value and proceed to next input
    4. If 'no': Allow user to re-enter value
    5. NEVER proceed without final confirmation

    DATA TYPE VALIDATION:
    - STRING: Any text value
    - INT: Integer numbers only
    - FLOAT: Decimal numbers
    - BOOLEAN: true/false, yes/no, 1/0
    - DATE: YYYY-MM-DD format
    - DATETIME: ISO 8601 format

    COLLECTION PRESENTATION:
    "Now configuring: [X of Y inputs]

    Task: {task_name}
    Input: {input_name} ({data_type})
    Description: {description}
    Required: {Yes/No}
    Default: {default_value or 'None'}

    Please provide a value, type 'default' to use default, or 'skip' if optional:"

    CRITICAL RULES:
    - NEVER upload files for primitive data types
    - Store all primitive values in memory only
    - Always confirm default values with user
    - ALWAYS get final confirmation before proceeding to next input
    - Respect required vs optional based on input.required attribute
    - Validate data types before storing

    Args:
        task_name: Name of the task this input belongs to
        input_name: Name of the input parameter
        user_value: Value provided by user (optional)
        use_default: Whether to use default value (requires confirmation)

    Returns:
        Dict containing parameter value and storage info
    """
    try:
        task = None
        tasks_resp = rule.fetch_task_api(params={
            "name": task_name}, ctx=ctx)

        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            task = TaskVO.from_dict(tasks_resp["items"][0])
        if not task:
            return {"success": False, "error": f"Task '{task_name}' not found in available tasks"}

        # Find the specific input
        task_input = None
        available_task_inputs=[]
        for inp in task.inputs:
            available_task_inputs.append(inp.name)
            if inp.name == input_name:
                task_input = inp
                break

        if not task_input:
            return {"success": False, "error": f"Input '{input_name}' not found in task '{task_name}'. Available inputs are: {available_task_inputs}"}

        # Check if this input is required
        is_required = task_input.required
        has_default = bool(task_input.defaultValue)

        # Handle different input scenarios
        if use_default and has_default:
            # User wants to use default - need confirmation
            return {"success": True, "task_name": task_name, "input_name": input_name, "needs_default_confirmation": True, "default_value": task_input.defaultValue, "data_type": task_input.dataType, "required": is_required, "confirmation_message": f"I can fill this with the default value: '{task_input.defaultValue}'. Confirm? (yes/no)", "message": "Default value needs user confirmation before proceeding"}

        elif user_value is not None:
            # User provided a value - validate it
            validation_result = rule.validate_parameter_value(
                user_value, task_input.dataType)
            if not validation_result["valid"]:
                return {"success": False, "error": "Invalid value format", "validation_errors": validation_result["errors"], "expected_type": task_input.dataType, "message": "Please provide a valid value"}

            # Value is valid - need FINAL confirmation before storing
            return {"success": True, "task_name": task_name, "input_name": input_name, "validated_value": validation_result["converted_value"], "needs_final_confirmation": True, "data_type": task_input.dataType, "required": is_required, "final_confirmation_message": f"You entered: '{validation_result['converted_value']}'. Is this correct? (yes/no)", "message": "Value validated - needs final confirmation before storing"}

        else:
            # Need to collect input from user
            presentation = rule.generate_parameter_presentation(
                task_input, task_name)
            return {"success": True, "task_name": task_name, "input_name": input_name, "needs_user_input": True, "presentation": presentation, "data_type": task_input.dataType, "required": is_required, "has_default": has_default, "default_value": task_input.defaultValue if has_default else None, "message": "Ready to collect parameter input from user"}

    except Exception as e:
        return {"success": False, "error": f"Failed to process parameter input: {e}"}


@mcp.tool()
def confirm_parameter_input(task_name: str, input_name: str, rule_input_name:str, confirmed_value: str, explaination: str, confirmation_type: str = "final", rule_name: str = None, ctx: Context | None = None) -> dict[str, Any]:
    """Confirm and store parameter input after user validation.

    CONFIRMATION PROCESSING (Enhanced with Automatic Rule Updates):
    - Handles final confirmation of parameter values
    - Stores confirmed values in memory
    - Supports both default value confirmation and final value confirmation
    - MANDATORY step before proceeding to next input
    - NEW: Automatically updates rule with parameter if rule_name provided

    CONFIRMATION TYPES (Preserved):
    - "default": User confirmed they want to use default value
    - "final": User confirmed their entered value is correct
    - Both types require explicit user confirmation

    STORAGE RULES (Enhanced):
    - Store all confirmed values in memory (never upload files)
    - Only store after explicit user confirmation
    - Include metadata about confirmation type and timestamp
    - NEW: Automatic rule update with parameter data

    AUTOMATIC RULE UPDATE PROCESS:
    If rule_name is provided, this tool automatically:
    1. Fetches the current rule structure
    2. Adds the parameter to spec.inputs
    3. Updates spec.inputsMeta__ with parameter metadata
    4. Calls create_rule() to save the updated rule
    5. Rule status will be auto-detected based on completion

    Args:
        task_name: Name of the task this input belongs to
        input_name: Name of the input parameter
        rule_input_name: Must be one of the values defined in the rule structure's inputs
        confirmed_value: The value user confirmed
        explanation: Add explanation only if dataType is JQ_EXPRESSION or SQL_EXPRESSION. This field provides details about the confirmed_value.
        confirmation_type: Type of confirmation ("default" or "final")
        rule_name: Optional rule name for automatic rule updates

    Returns:
        Dict containing stored value confirmation and rule update status
    """
    try:
        task = None
        tasks_resp = rule.fetch_task_api(params={"name": task_name}, ctx=ctx)
        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            task = TaskVO.from_dict(tasks_resp["items"][0])
        if not task:
            return {"success": False, "error": f"Task '{task_name}' not found in available tasks"}

        # Find the specific input
        task_input = None
        available_task_inputs=[]
        for inp in task.inputs:
            available_task_inputs.append(inp.name)
            if inp.name == input_name:
                task_input = inp
                break

        if not task_input:
            return {"success": False, "error": f"Input '{input_name}' not found in task '{task_name}'. Available inputs are: {available_task_inputs}"}

        # Validate the confirmed value (preserved validation)
        validation_result = rule.validate_parameter_value(confirmed_value, task_input.dataType)
        if not validation_result["valid"]:
            return {"success": False, "error": "Confirmed value is invalid", "validation_errors": validation_result["errors"]}

        # NEW: AUTOMATIC RULE UPDATE WITH NEW PARAMETER (if rule_name provided)
        rule_update_success = False
        rule_status = "UNKNOWN"
        rule_progress = 0
        
        if rule_name:
            try:
                # Fetch current rule
                current_rule = fetch_rule(rule_name, ctx)
                if current_rule["success"]:
                    rule_structure = current_rule["rule_structure"]
                    
                    # Add parameter to rule structure
                    rule_structure["spec"]["inputs"][rule_input_name] = validation_result["converted_value"]
                    
                    # Add/update parameter metadata
                    input_meta = {
                        "name": rule_input_name,
                        "dataType": task_input.dataType,
                        "required": task_input.required,
                        "defaultValue": validation_result["converted_value"]
                    }

                    # Add explanation if dataType is JQ_EXPRESSION or SQL_EXPRESSION
                    if task_input.dataType in ["JQ_EXPRESSION", "SQL_EXPRESSION"]:
                        input_meta["explanation"] = explaination
                    
                    if hasattr(task_input, 'format') and task_input.format:
                        input_meta["format"] = task_input.format
                    elif task_input.dataType.upper() == "FILE" and "." in input_meta["defaultValue"]:
                        input_meta["format"] = input_meta["defaultValue"].split(".")[-1]

                    # Update metadata list
                    existing_meta = rule_structure["spec"]["inputsMeta__"]
                    rule_structure["spec"]["inputsMeta__"] = [m for m in existing_meta if m["name"] != rule_input_name]
                    rule_structure["spec"]["inputsMeta__"].append(input_meta)
                    
                    # Update rule - status auto-detected
                    update_result = create_rule(rule_structure, ctx)
                    rule_update_success = update_result["success"]
                    rule_status = update_result.get("detected_status", "UNKNOWN")
                    rule_progress = update_result.get("progress_percentage", 0)
                    
            except Exception as update_error:
                # Log the error but don't fail the parameter processing
                print(f"Warning: Rule update failed for {rule_name}: {update_error}")

        # Store the confirmed value in memory (preserved logic)
        return {
            "success": True,
            "task_name": task_name,
            "input_name": input_name,
            "stored_value": validation_result["converted_value"],
            "data_type": task_input.dataType,
            "required": task_input.required,
            "storage_type": "MEMORY",
            "confirmation_type": confirmation_type,
            "timestamp": datetime.now().isoformat(),
            "rule_name": rule_name,
            "rule_updated": rule_update_success,
            "rule_status": rule_status,
            "rule_progress": rule_progress,
            "message": f"Parameter value confirmed and stored in memory for {input_name}. Rule '{rule_name}' {'updated automatically' if rule_update_success and rule_name else 'not updated (no rule_name provided)'}."
        }

    except Exception as e:
        return {"success": False, "error": f"Failed to confirm parameter input: {e}"}


# INPUT VERIFICATION TOOLS - MANDATORY WORKFLOW STEPS
@mcp.tool()
def prepare_input_collection_overview(selected_tasks: list[dict[str, str]], ctx: Context | None = None) -> dict[str, Any]:
    """
    INPUT COLLECTION OVERVIEW & RULE CREATION

    Prepare and present input collection overview before starting any input collection.

    MANDATORY FIRST STEP - INPUT OVERVIEW PROCESS (Enhanced):
    This tool MUST be called before collecting any inputs. It analyzes all selected tasks and presents a complete overview of what inputs will be needed.

    ENHANCED WITH AUTOMATIC RULE CREATION:
    After user confirms the input overview, this tool automatically creates the initial rule structure with selected tasks. The rule will be saved with DRAFT status and can be progressively updated as inputs are collected.

    **MANDATORY WORKFLOW ENFORCEMENT - CRITICAL INSTRUCTION:**
    - AFTER user confirms the input overview, IMMEDIATELY call create_rule() with initial structure.
    - This call is MANDATORY and CANNOT be skipped or deferred.
    - The initial rule structure MUST be created before any input collection begins.
    - BLOCK all subsequent input collection if initial rule creation fails.
    - NEVER proceed to input collection without successful initial rule creation.
    - If create_rule() fails, STOP workflow and resolve the issue before continuing.
    - The rule creation establishes the foundation for progressive updates during input collection.


    **ENFORCEMENT STEPS:**
    1. Present overview to user
    2. Get user confirmation
    3. **IMMEDIATELY call create_rule() with initial structure that MUST INCLUDE inputs and inputsMeta__ sections WITH ACTUAL INPUT DATA - DO NOT LEAVE inputs and inputsMeta__ SECTION EMPTY - INPUTS AND INPUTSMETA__ ARE MANDATORY CORE COMPONENTS THAT MUST CONTAIN THE REQUIRED INPUT MAPPINGS - THIS IS NON-NEGOTIABLE - NO EXCEPTIONS**
    4. Verify rule creation success before proceeding
    5. Only then allow input collection to begin

    TASK-BY-TASK INPUT COLLECTION & VALIDATION (CRITICAL ENFORCEMENT):
    ═══════════════════════════════════════════════════════════════════
    MANDATORY WORKFLOW FOR EACH TASK:
    
    FOR EACH TASK in selected_tasks:
        STEP 1: Collect ALL inputs for current task
                - Use collect_template_input() for file/template inputs
                - Use collect_parameter_input() for parameter inputs
                - Wait for the current task inputs to be collected
        
        STEP 2: **MANDATORY EXECUTION** (CANNOT BE SKIPPED)
                ⛔ THIS STEP CANNOT BE SKIPPED ⛔
                - Call execute_task(task_name, collected_inputs_for_this_task, application_config)
                - This MUST happen IMMEDIATELY after all task inputs are collected
                - BLOCK progression if execution fails
                - If execution fails:
                  * Show execution errors to user
                  * Allow input correction
                  * Re-execute with corrected inputs
                  * Only proceed when execution succeeds
                - On success:
                  * Store the REAL outputs from this task
                  * Use these outputs as inputs for dependent tasks
                  * Display output files to user
        
        STEP 3: Move to next task ONLY after the task execution succeeds
                - Task Execution success = prerequisite for next task
                - No task can start input collection without previous task execution completing successfully
                - Use the REAL outputs from the executed task as inputs for dependent tasks

    ❌ PROHIBITED ACTIONS:
    - Collecting inputs for Task N+1 without executing Task N
    - Skipping execution "to save time"
    - Assuming execution will happen "later"
    - Moving to final rule creation without executing all tasks

    ✅ CORRECT WORKFLOW:
    Task1 Inputs → Execute Task1 → Show Results → Task2 Inputs → Execute Task2 → Show Results → Task3 Inputs → Execute Task3 → Show Results → Complete Rule

    ❌ WRONG WORKFLOW:
    Task1 Inputs → Task2 Inputs → Task3 Inputs → [Try to execute later]


    **SELECTIVE INPUT INCLUSION:**
    - DO NOT automatically include ALL task inputs in initial rule creation.
    - Only include inputs that are REQUIRED or explicitly needed for the user's use case.
    - Skip optional inputs unless user specifically requests them.
    - Additional inputs can be added later if needed during execution or refinement.

    **FAILURE HANDLING:**
    - If user confirms but create_rule() fails → STOP and fix issue.
    - If user declines → End workflow, no rule creation needed.
    - If create_rule() succeeds → Proceed to task-wise input collection and execution.
    - NEVER skip the create_rule() call after user confirmation.


    HANDLES DUPLICATE INPUT NAMES WITH TASK ALIASES (Preserved):
    - Creates unique identifiers for each task-alias-input combination.
    - Format: "{task_alias}.{input_name}" for uniqueness.
    - Prevents conflicts when multiple tasks have same input names or same task used multiple times.
    - Maintains clear mapping between task aliases and their specific inputs.
    - Task aliases should be simple, meaningful step indicators (e.g., "step1", "validation", "processing").

    OVERVIEW REQUIREMENTS (Preserved):
    1. Analyze ALL selected tasks with their aliases for input requirements.
    2. Categorize inputs: templates vs parameters.
    3. Create unique identifiers for each task-alias-input combination.
    4. Count total inputs needed.
    5. Present clear overview to user.
    6. Get user confirmation before proceeding.
    7. Return structured overview for systematic collection.
    8. NEW: Automatically create initial rule after user confirmation.

    OVERVIEW PRESENTATION FORMAT (Enhanced with Validation):
    
    INPUT COLLECTION OVERVIEW:

    I've analyzed your selected tasks. Here's what we need to configure:

    TASK 1: [TaskAlias] ([TaskName])
    ───────────────────────────────────
    Template Inputs:
    • [InputName] ([Format] file) - [Description]
      Unique ID: [TaskAlias.InputName]
    
    Parameter Inputs:
    • [InputName] ([DataType]) - [Description]
      Unique ID: [TaskAlias.InputName]
      Required: [Yes/No]
    
    ⚠️  EXECUTION CHECKPOINT: After collecting all Task 1 inputs, 
        execute_task() will be called to execute the task with real data before proceeding to Task 2.
    
    TASK 2: [TaskAlias] ([TaskName])
    ───────────────────────────────────
    [... similar structure ...]
    
    ⚠️  EXECUTION CHECKPOINT: After collecting all Task 2 inputs,
        execute_task() will be called to execute the task with real data before proceeding to Task 3.

    SUMMARY:
    - Total inputs needed: X
    - Template files: Y ([formats])
    - Parameter values: Z
    - Estimated time: ~[X] minutes
    - Execution checkpoints: [number of tasks]

    WORKFLOW:
    1. For each task in the rule:
        - Collect all required inputs for the task
        - Execute the task with real data using execute_task()
        - Mark the task as executed (✓)
        - Store REAL outputs for use by dependent tasks
    2. After all tasks are executed → proceed to final rule completion

    Ready to start task-by-task input collection with execution checkpoints?

    CRITICAL WORKFLOW RULES:
    - ALWAYS call this tool first before any input collection.
    - NEVER start collecting inputs without user seeing overview.
    - NEVER proceed without user confirmation.
    - Create unique task_alias.input identifiers to avoid conflicts.
    - Show clear task-alias-input relationships to user.
    - NEW: Collect inputs task-by-task and execute each task immediately after collection.
    - NEW: Use REAL outputs from executed tasks as inputs for dependent tasks.
    - NEW: Create initial rule structure after user confirmation.

    CRITICAL REQUIREMENTS:
    - Input names: alphanumeric + underscore only (auto-sanitize with re.sub(r'[^a-zA-Z0-9_]', '_', name))
    - Collection order: Complete ALL inputs for each task one by one (Task 1 → execute Task 1 → Task 2 → execute Task 2 → Task 3 → execute Task 3)
    - Within each task: collect all inputs, then execute using 'execute_task()' to get real outputs before proceeding
    - If a task (e.g., Task 2) has input files or other inputs that depend on a previous task, use the REAL output from the executed previous task as the input. Do NOT generate sample data.
    - If the previous task has not been executed yet, execute it first to obtain real outputs.

    ARGS:
    - selected_tasks: list of dicts with 'task_name' and 'task_alias'
    Example:
    [
        {"task_name": "data_validation", "task_alias": "step1"},
        {"task_name": "data_processing", "task_alias": "step2"},
        {"task_name": "data_validation", "task_alias": "final_check"}
    ]

    Returns:
        Dict containing structured input overview and collection plan with unique identifiers,
        plus automatic rule creation capability after user confirmation, with explicit
        execution checkpoints for each task
    """

    if not selected_tasks:
        return {"success": False, "error": "No tasks selected for input analysis"}

    try:
        input_analysis = {
            "template_inputs": [], 
            "parameter_inputs": [], 
            "total_count": 0, 
            "template_count": 0,
            "parameter_count": 0, 
            "estimated_minutes": 0, 
            "unique_input_map": {},
            "task_alias_map": {},
            "task_input_groups": {}  # NEW: Group inputs by task for validation tracking
        }

        # Validate input format and task aliases
        for task_info in selected_tasks:
            if not isinstance(task_info, dict) or "task_name" not in task_info or "task_alias" not in task_info:
                return {"success": False, "error": "Each task must be a dict with 'task_name' and 'task_alias' keys"}
            
            task_alias = task_info["task_alias"].strip()
            if not task_alias:
                return {"success": False, "error": f"Task alias is required for task {task_info['task_name']}"}
            
            if len(task_alias) > 100:
                return {"success": False, "error": f"Task alias '{task_alias}' exceeds 100 character limit"}
            
            # Check for duplicate aliases
            if task_alias in input_analysis["task_alias_map"]:
                return {"success": False, "error": f"Duplicate task alias '{task_alias}' found. Each alias must be unique."}
            
            # Store task alias mapping
            input_analysis["task_alias_map"][task_alias] = {
                "task_name": task_info["task_name"],
                "purpose": task_info.get("purpose", "")
            }
            
            # Initialize task input group for validation tracking
            input_analysis["task_input_groups"][task_alias] = {
                "task_name": task_info["task_name"],
                "task_alias": task_alias,
                "inputs": [],
                "input_count": 0,
                "validation_required": True
            }

        # Get available tasks
        available_tasks = []
        tasks_resp = rule.fetch_task_api(params={"tags": "primitive"}, ctx=ctx)
        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            available_tasks = [TaskVO.from_dict(task) for task in tasks_resp["items"]]

        if not available_tasks:
            return {"success": False, "error": "No tasks loaded"}

        # Analyze each selected task with its alias
        for task_info in selected_tasks:
            task_name = task_info["task_name"]
            task_alias = task_info["task_alias"]
            task_purpose = task_info.get("purpose", "")

            # Find the task definition
            task = None
            for available_task in available_tasks:
                if available_task.name == task_name:
                    task = available_task
                    break

            if not task:
                continue

            # Process each input with unique identifier using task alias
            for inp in task.inputs:
                cleaned_input_name = validate_input_name(inp.name)
                unique_input_id = f"{task_alias}.{cleaned_input_name}"
                
                data_type = ""
                if inp.dataType:
                    data_type = inp.dataType

                input_info = {
                    "task_name": task_name,
                    "task_alias": task_alias, 
                    "task_purpose": task_purpose,
                    "input_name": inp.name,
                    "unique_input_id": unique_input_id,
                    "description": inp.description,
                    "data_type": data_type,
                    "required": inp.required,
                    "has_template": bool(inp.templateFile),
                    "format": inp.format if inp.templateFile else None,
                    "has_default": bool(inp.defaultValue),
                    "default_value": inp.defaultValue if inp.defaultValue else None
                }

                # Store in unique input map for easy lookup
                input_analysis["unique_input_map"][unique_input_id] = {
                    "task_name": task_name,
                    "task_alias": task_alias,
                    "input_name": inp.name,
                    "task_input_obj": {
                        "name": inp.name,
                        "description": inp.description,
                        "dataType": inp.dataType,
                        "required": inp.required,
                        "format": inp.format if inp.templateFile else None,
                    }
                }
                
                # Add to task input group for validation tracking
                input_analysis["task_input_groups"][task_alias]["inputs"].append(unique_input_id)
                input_analysis["task_input_groups"][task_alias]["input_count"] += 1

                if inp.templateFile or inp.dataType.upper() in ["FILE", "HTTP_CONFIG"]:
                    input_analysis["template_inputs"].append(input_info)
                    input_analysis["template_count"] += 1
                    input_analysis["estimated_minutes"] += 3
                else:
                    input_analysis["parameter_inputs"].append(input_info)
                    input_analysis["parameter_count"] += 1
                    input_analysis["estimated_minutes"] += 0.5

        input_analysis["total_count"] = input_analysis["template_count"] + input_analysis["parameter_count"]
        
        # Generate initial inputs, inputsMeta__ for rule creation
        initial_inputs = {}
        initial_inputs_meta = []
        
        # Track duplicate input names to handle conflicts
        input_name_counts = {}

        # Process only required inputs from template_inputs and parameter_inputs
        all_required_inputs = input_analysis["template_inputs"] + input_analysis["parameter_inputs"]
        
        for input_info in all_required_inputs:
            input_name = input_info["input_name"]
            task_alias = input_info["task_alias"]
            unique_input_id = input_info["unique_input_id"]
            
            # Get the task input object from unique_input_map
            task_input_obj = input_analysis["unique_input_map"][unique_input_id]["task_input_obj"]
            
            # Handle duplicate input names by creating unique names
            if input_name in input_name_counts:
                input_name_counts[input_name] += 1
                unique_name = f"{task_alias}_{input_name}"
            else:
                input_name_counts[input_name] = 1
                duplicate_count = sum(1 for other_input in all_required_inputs 
                                    if other_input["input_name"] == input_name and other_input["required"])
                if duplicate_count > 1:
                    unique_name = f"{task_alias}_{input_name}"
                else:
                    unique_name = input_name
            
            # Set initial value based on dataType
            data_type = getattr(task_input_obj, "dataType", None)
            if data_type:
                data_type_upper = data_type.upper()
            else:
                data_type_upper = ""
            if data_type_upper in ["FILE", "HTTP_CONFIG"]:
                initial_value = ""
            elif data_type_upper == "BOOLEAN":
                initial_value = False
            elif data_type_upper in ["INT", "INTEGER"]:
                initial_value = 0
            elif data_type_upper == "FLOAT":
                initial_value = 0.0
            elif data_type_upper in ["STRING", "TEXT"]:
                initial_value = ""
            elif data_type_upper in ["DATE", "DATETIME"]:
                initial_value = ""
            else:
                initial_value = ""
            
            initial_inputs[unique_name] = initial_value
            
            input_meta = {
                "name": unique_name,
                "dataType": data_type if data_type else "",
                "defaultValue": initial_value,
                "showField": True,
                "required": getattr(task_input_obj, "required", False),
                "allowedValues": [],
                "repeated": False
            }
            
            if hasattr(task_input_obj, 'format') and getattr(task_input_obj, 'format', None):
                input_meta["format"] = getattr(task_input_obj, 'format')
            
            initial_inputs_meta.append(input_meta)

        # Generate overview presentation with validation checkpoints
        overview_text = rule.generate_input_overview_presentation_with_validation_checkpoints(
            input_analysis
        )
        
        return {
            "success": True,
            "input_analysis": input_analysis,
            "overview_presentation": overview_text,
            "task_alias_map": input_analysis["task_alias_map"],
            "task_input_groups": input_analysis["task_input_groups"],  # NEW: For validation tracking
            "mandatory_collection_plan": {
                "step1": "Collect inputs task-wise for all defined tasks. For each task, gather all required inputs (e.g., if a task has three inputs, collect all three before proceeding).",
                "step2": "After collecting all inputs for a specific task, **MANDATORY EXECUTION CHECKPOINT** - call execute_task(task_name, collected_inputs_dict, application_config) to execute the task with real data.",
                "step3": "If execution fails, allow user to correct inputs and re-execute. Only proceed to next task when execution succeeds.",
                "step4": "Once a task executes successfully, use its REAL outputs as inputs for subsequent dependent tasks. Proceed to collect inputs for the next task and repeat the same execution process.",
                "step5": "After completing and executing all tasks, perform a final cross-task consistency check to confirm all outputs are available and rule is ready for creation.",
                "step6": "Finally, create the rule with verified task alias mappings and I/O mappings based on actual executed outputs.",
                "critical_note": "**EXECUTION IS MANDATORY AND CANNOT BE SKIPPED** - Each task MUST be executed with real data before moving to the next task. This creates checkpoints ensuring real outputs are available for dependent tasks throughout the workflow."
            },
            "rule_creation_ready": True,
            "selected_tasks": selected_tasks,
            "initial_inputs": initial_inputs,
            "initial_inputs_meta": initial_inputs_meta,
            "validation_checkpoint_count": len(selected_tasks),  # NEW: Number of validation checkpoints
            "message": "Input overview prepared with task aliases and validation checkpoints. Present to user and get confirmation before proceeding.",
            "next_action": "Show overview_presentation to user and wait for confirmation, then create initial rule and follow 'mandatory_collection_plan' with STRICT validation enforcement"
        }

    except Exception as e:
        return {"success": False, "error": f"Failed to prepare input overview: {e}"}

@mcp.tool()
def execute_task(task_name: str, task_inputs: dict[str, Any], application: dict[str, Any] = None, ctx: Context | None = None) -> dict[str, Any]:
    """
    Execute a specific task with real data after collecting all required inputs.

    **This tool executes tasks with REAL data, not sample data.**
    If any input depends on a previous task's output and that output is not available,
    the dependent task(s) MUST be executed first to obtain the real output.

    ===============================================================================
    EXECUTION CONTEXT
    ===============================================================================
    - This tool MUST be called after collecting the inputs for a task.
    - Execution is sequential: execute Task 1 → then Task 2 → etc.
    - No task may proceed until its dependent tasks have been executed.
    - On execution failure, provide detailed error feedback.

    ===============================================================================
    DEPENDENCY & REAL DATA HANDLING
    ===============================================================================
    If a task requires input from a previous task (dataset, file, or structured output):

    1. **Use real task output when available**
        - If the dependent task was already executed and produced outputs:
            → Use those outputs as the input.
            → Do NOT generate synthetic/sample data.
            → Do NOT re-run the previous task unnecessarily.

    2. **If required previous task output does NOT exist**
        - The assistant MUST:
            - Explain *why* execution of the previous task is required.
            - Automatically execute the previous task (and any required tasks in the chain).
            - **After execution, display all execution results and outputs.**
            - NO user confirmation should be requested—only explanation.
            - Use the REAL output from the executed task as input.

    3. **If executing a required previous task fails**
        - The assistant MUST:
            - Explain clearly why the task failed.
            - Ask the user to provide the required input data manually.
        - User-provided data becomes the fallback input.

    4. **Only execute what is needed**
        - Execute ONLY the minimal set of tasks whose outputs are required.
        - **Every executed task must have its results shown to the user immediately.**

    ===============================================================================
    APPLICATION CONFIGURATION
    ===============================================================================
    Application credentials are REQUIRED if the task's appType is NOT 'nocredapp'.

    If the task requires application credentials (appType != 'nocredapp'):
    - Application config must be provided with:
        - appName: Application class name
        - appURL: Application URL (optional, can be empty string)
        - credentialType: Type of credentials
        - credentialValues: Actual credential key-value pairs
    - OR applicationId if using existing saved application

    If the task's appType is 'nocredapp':
    - Application configuration can be omitted (pass None or empty)
    - The system will automatically use the hardcoded nocredapp application structure:
      {
          "applicationType": "NoCredApp",
          "appURL": "",
          "credentialType": "NoCred",
          "credentialValues": {"Dummy": ""},
          "appTags": {"appType": ["nocredapp"], "environment": ["logical"], "execlevel": ["app"]}
      }

    ===============================================================================
    TASK EXECUTION FLOW
    ===============================================================================
    1. Receive task name and collected inputs
    2. Check if any input depends on previous task output
    3. For dependency inputs:
        a. Check if previous task output exists
        b. If not, execute previous task first
        c. Use real output as input value
    4. Prepare execution payload with real data
    5. Call task execution API
    6. Parse and return execution results with output file URLs

    ===============================================================================
    REQUEST BODY FORMAT
    ===============================================================================
```json
    {
        "taskname": "TaskName",
        "application": {
            "appName": "ApplicationClassName",
            "appURL": "https://app.url.com",
            "credentialType": "CredentialTypeName",
            "credentialValues": {
                "key1": "value1",
                "key2": "value2"
            },
            "appTags": [Complete object from of 'appTags' from the task in the rule]
        },
        "taskInputs": {
            "inputs": {
                "InputName1": "value_or_file_url",
                "InputName2": "value_or_file_url"
            }
        }
    }
```

    ===============================================================================
    Args:
        task_name: Name of the task to execute
        task_inputs: Dictionary containing key-value pairs of task inputs
                    Format: {"input_name": "value" or file_url}
        application: Optional application configuration for tasks requiring credentials
                    Format: {
                        "appName": "ApplicationClassName",
                        "appURL": "https://...",
                        "credentialType": "...",
                        "credentialValues": {...},
                        "appTags": [Complete object from of 'appTags' from the task in the rule]
                    }
                    OR {"applicationId": "existing-app-id", "appTags": [Complete object from of 'appTags' from the task in the rule]}

    Returns:
        Dict containing:
        {
            "success": bool,
            "execution_status": "COMPLETED" | "FAILED",
            "task_name": str,
            "task_inputs": dict,
            "outputs": dict,  # Output file URLs and values
            "errors": list,
            "message": str,
            "next_action": str
        }
    """

    try:
        # Step 1: Get task details to understand expected input/output structure
        task_details = get_task_details(task_name, ctx)
        if task_details.get("error"):
            return {
                "success": False,
                "execution_status": "FAILED",
                "task_name": task_name,
                "error": f"Could not fetch task details: {task_details['error']}",
                "next_action": "verify_task_name"
            }
        
        task_inputs_spec = task_details.get("inputs", [])
        task_app_tags = task_details.get("appTags", {})
        task_app_types = task_app_tags.get("appType", [])

        # Step 2: Check if task requires application credentials
        # Application is required only if appType is NOT 'nocredapp'
        is_nocredapp = task_app_types and all(t.lower() == "nocredapp" for t in task_app_types)
        requires_app = task_app_types and not is_nocredapp

        if requires_app and not application:
            return {
                "success": False,
                "execution_status": "FAILED",
                "task_name": task_name,
                "error": f"Task '{task_name}' requires application credentials but none provided. Application credentials are required because appType is not 'nocredapp'.",
                "required_app_type": task_app_types,
                "next_action": "provide_application_credentials",
                "hint": "Use get_applications_for_tag() to find existing applications or provide new credentials"
            }

        # For nocredapp tasks, use hardcoded application structure if no application provided
        if is_nocredapp and not application:
            application = {
                "applicationType": "NoCredApp",
                "appURL": "",
                "credentialType": "NoCred",
                "credentialValues": {
                    "Dummy": ""
                },
                "appTags": {
                    "appType": ["nocredapp"],
                    "environment": ["logical"],
                    "execlevel": ["app"]
                }
            }

        # Step 3: Validate all required inputs are present
        validated_inputs = {}
        missing_inputs = []
        
        for input_spec in task_inputs_spec:
            input_name = input_spec["name"]
            is_required = input_spec.get("required", False)
            
            if input_name in task_inputs:
                input_value = task_inputs[input_name]
                
                # Check if input value is a placeholder for previous task output
                if isinstance(input_value, str) and (
                    input_value == "<<FROM_PREVIOUS_TASK>>" or
                    input_value.startswith("<<") or
                    "previous_task" in input_value.lower()
                ):
                    return {
                        "success": False,
                        "execution_status": "FAILED",
                        "task_name": task_name,
                        "error": f"Input '{input_name}' requires output from a previous task that hasn't been executed",
                        "input_name": input_name,
                        "next_action": "execute_dependent_task",
                        "hint": "Execute the dependent task first to get real output, then use that output as input here"
                    }
                
                validated_inputs[input_name] = input_value
            elif is_required:
                missing_inputs.append(input_name)
        
        if missing_inputs:
            return {
                "success": False,
                "execution_status": "FAILED",
                "task_name": task_name,
                "error": f"Missing required inputs: {missing_inputs}",
                "missing_inputs": missing_inputs,
                "next_action": "collect_missing_inputs"
            }
        
        # Step 4: Build execution request body
        request_body = {
            "taskname": task_name,
            "taskInputs": {
                "inputs": validated_inputs
            }
        }
        
        # Add application config if provided
        if application:
            if "applicationId" in application:
                # Using existing application
                request_body["application"] = {
                    "applicationId": application["applicationId"],
                    "appTags": application.get("appTags", {})
                }
            else:
                # Using new credentials
                request_body["application"] = {
                    "appName": application.get("appName") or application.get("applicationType"),
                    "appURL": application.get("appURL", ""),
                    "credentialType": application.get("credentialType"),
                    "credentialValues": application.get("credentialValues", {})
                }
        
        # Step 5: Execute the task
        logger.info(f"Executing task '{task_name}' with inputs: {list(validated_inputs.keys())}")
        
        response = rule.execute_task(request_body, ctx)
        
        if not response:
            return {
                "success": False,
                "execution_status": "FAILED",
                "task_name": task_name,
                "task_inputs": validated_inputs,
                "error": "Task execution API returned no response",
                "next_action": "retry_execution"
            }
        
        # Step 6: Parse execution response
        task_outputs = response.get("taskOutputs", {})
        outputs = task_outputs.get("Outputs", {})
        errors = response.get("errors", [])
        status = response.get("status", "UNKNOWN")
        
        # Check for execution errors
        if errors and len(errors) > 0:
            error_details = []
            for error in errors:
                if isinstance(error, dict):
                    error_details.append({
                        "field": error.get("field", "unknown"),
                        "message": error.get("message", "Execution failed"),
                        "type": error.get("type", "execution_error")
                    })
                else:
                    error_details.append({"message": str(error)})
            
            return {
                "success": False,
                "execution_status": "FAILED",
                "task_name": task_name,
                "task_inputs": validated_inputs,
                "outputs": outputs,
                "errors": error_details,
                "message": f"❌ Task '{task_name}' execution failed. Please review errors.",
                "next_action": "fix_execution_errors"
            }
        
        # Step 7: Return successful execution results
        return {
            "success": True,
            "execution_status": "COMPLETED",
            "task_name": task_name,
            "task_inputs": validated_inputs,
            "outputs": outputs,
            "output_files": {k: v for k, v in outputs.items() if isinstance(v, str) and (v.startswith("http") or v.startswith("/"))},
            "message": f"✅ Task '{task_name}' executed successfully.",
            "next_action": "proceed_to_next_task",
            "hint": "Use the outputs from this task as inputs for dependent tasks"
        }

    except Exception as e:
        logger.error(f"Exception during task execution: {e}")
        return {
            "success": False,
            "execution_status": "FAILED",
            "task_name": task_name,
            "error": f"Exception during execution: {str(e)}",
            "exception_type": type(e).__name__,
            "next_action": "review_exception"
        }

def add_rule_tag(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Add MCP tag to a rule.
    
    Args:
        rule_name: Name of the rule to add tags to
        
    Returns:
        Dict with tag addition results
    """
    try:
        headers = wsutils.create_header(ctx)
        
        # Prepare request data for adding rule tags
        request_data = {
            "ruleNames": [rule_name],
            "tags": ["MCP"],
            "operation": "ADD"
        }
        
        wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_UPDATE_RULE_TAGS),
            data=json.dumps(request_data),
            header=headers
        )

        return {
            "success": True,
            "rule_name": rule_name,
            "message": f"MCP tag added successfully to rule '{rule_name}'"
        }

    except Exception as e:
        return {
            "success": False,
            "rule_name": rule_name,
            "message": f"Error: {e}"
        }


@mcp.tool()
def generate_design_notes_preview(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Generate design notes preview for user confirmation before actual creation.

    ## DESIGN NOTES PREVIEW GENERATION

    This tool generates a complete Jupyter notebook structure as a dictionary for user review. The MCP will create the full notebook content with 7 standardized sections based on rule context and metadata, then return it for user confirmation.

    ## DESIGN NOTES TEMPLATE STRUCTURE REQUIREMENTS

    The MCP should generate a Jupyter notebook (.ipynb format) with exactly 7 sections:

    ### SECTION 1: Evidence Details
    **DESCRIPTION:** System identification and rule purpose documentation

    **CONTENT REQUIREMENTS:**
    - Table with columns: System | Source of data | Frameworks | Purpose
    - System: {TARGET_SYSTEM_NAME} (all lowercase")
    - Source: Always 'compliancecow'
    - Frameworks: Always '-'
    - Purpose: Use rule's purpose from metadata
    - RecommendedEvidenceName: {RULE_OUTPUT_NAME} (use rule's primary compliance output, exclude LogFile)
    - Description: Use rule description from metadata
    - Reference: Include actual API documentation links that the rule uses (extract from task specifications, no placeholder values)

    **FORMAT:** Markdown cell with table and code blocks only

    ### SECTION 2: Define the System Specific Data (Extended Data Schema)
    **DESCRIPTION:** System-specific raw data structure definition with detailed breakdown

    **CONTENT REQUIREMENTS:**

    #### Step 2a: Inputs
    - Generate numbered list from rule's spec.inputs
    - Format: "{NUMBER}. **{INPUT_NAME}({INPUT_DATA_TYPE})** - {INPUT_DESCRIPTION}"
    - Include all inputs with their types and purposes

    #### Step 2b: API & Flow
    - Generate numbered list of API endpoints based on target system
    - Format: "{NUMBER}. {HTTP_METHOD} {URL} - {BRIEF_DESCRIPTION}"
    - Include only actual API endpoints that this specific rule uses for data collection
    - Extract from task specifications, not generic templates

    #### Step 2c: Define the Extended Schema
    - Generate large JSON code block with actual API response structure
    - Use system-specific field names and realistic data values
    - Include all fields that will be processed by the rule

    **FORMAT:** Markdown headers with detailed lists + large JSON code block

    ### SECTION 3: Define the Standard Schema
    **DESCRIPTION:** Standardized compliance data format documentation

    **CONTENT REQUIREMENTS:**
    - Header explaining standard schema purpose
    - JSON code block with complete standardized structure containing:
    * System: based on target system (lowercase)
    * Source: Always 'compliancecow'
    * Resource info: ResourceID, ResourceName, ResourceType, ResourceLocation, ResourceTags, ResourceURL
    * System-specific data fields based on actual rule output columns, if unavailable then generate based on rule details
    * Compliance fields: ValidationStatusCode, ValidationStatusNotes, ComplianceStatus, ComplianceStatusReason
    * Evaluation and action fields: EvaluatedTime, UserAction, ActionStatus, ActionResponseURL (UserAction, ActionStatus, ActionResponseURL are empty by default)

    #### Step 3a: Sample Data
    - Generate markdown table with ALL standard schema columns in same order - include all columns even if empty
    - Include three complete example rows with realistic, system-specific data
    - Use proper data formatting and realistic identifiers

    **FORMAT:** JSON code block + comprehensive markdown table

    ### SECTION 4: Describe the Compliance Taxonomy
    **DESCRIPTION:** Status codes and compliance definitions

    **CONTENT REQUIREMENTS:**
    - Table with columns: ValidationStatusCode | ValidationStatusNotes | ComplianceStatus | ComplianceStatusReason
    - ValidationStatusCode: **CRITICAL FORMAT REQUIREMENT** - Rule-specific codes must strictly follow this exact format:
        * Each word must be exactly 3-4 characters long
        * Words must be separated by underscores (_)
        * Use ALL UPPERCASE letters
        * Create codes that directly relate to the rule's compliance purpose
        * Examples: CODE_OWN_HAS_PR_REV (code ownership has pull request review), REPO_SEC_SCAN_PASS (repository security scan passed), AUTH_MFA_ENBL (authentication multi-factor enabled)
        * **DO NOT** use generic codes like "PASS" or "FAIL" 
        * **DO NOT** exceed 4 characters per word
        * **DO NOT** use special characters other than underscores
        * Generate 4-6 different status codes covering various compliance scenarios
    - Detailed compliance reasons specific to the rule's purpose
    - Both COMPLIANT and NON_COMPLIANT scenarios

    **FORMAT:** Markdown cell with table

    ### SECTION 5: Calculation for Compliance Percentage and Status
    **DESCRIPTION:** Percentage calculations and status logic

    **CONTENT REQUIREMENTS:**
    - Header explaining compliance calculation methodology
    - Code cell with calculation logic:
    * TotalCount = Count of 'COMPLIANT' and 'NON_COMPLIANT' records
    * CompliantCount = Count of 'COMPLIANT' records
    * CompliancePCT = (CompliantCount / TotalCount) * 100
    * Status determination rules:
        - COMPLIANT: 100%
        - NON_COMPLIANT: 0% to less than 100%
        - NOT_DETERMINED: If no records are found

    **FORMAT:** Markdown header cell + Code cell with calculation logic

    ### SECTION 6: Describe (in words) the Remediation Steps for Non-Compliance
    **DESCRIPTION:** Non-compliance remediation procedures

    **CONTENT REQUIREMENTS:**
    - Can be "N/A" if no specific remediation steps apply
    - When applicable, provide:
    * Immediate Actions required
    * Short-term remediation steps
    * Long-term monitoring approaches
    * Responsible parties and timeframes
    - System-agnostic guidance that can be customized

    **FORMAT:** Markdown cell with detailed remediation procedures

    ### SECTION 7: Control Setup Details
    **DESCRIPTION:** Rule configuration and implementation details

    **CONTENT REQUIREMENTS:**
    - Table with two columns: Control Details | (Values)
    - Required fields (only these):
    * RuleName: Use actual rule name
    * PreRequisiteRuleNames: Default to 'N/A' or list dependencies
    * ExtendedSchemaRuleNames: Default to 'N/A' or list related rules
    * ApplicationClassName: Fetch all appType values from spec.tasks array, combine them, remove duplicates, and format as comma-separated values
    * PostSynthesizerName: Default to 'N/A' or specify if used

    **FORMAT:** Markdown table with control configuration details

    ## JUPYTER NOTEBOOK METADATA REQUIREMENTS

    - Include proper notebook metadata (colab, kernelspec, language_info)
    - Set nbformat: 4, nbformat_minor: 0
    - Use appropriate cell metadata with unique IDs for each section
    - Ensure proper markdown and code cell formatting

    ## MCP CONTENT POPULATION INSTRUCTIONS

    The MCP should extract the following information from the rule context:
    - Rule name, purpose, description from rule metadata
    - System name from appType (clean by removing connector suffixes like "-connector")
    - Task details from spec.tasks array
    - Input specifications from spec.inputs and spec.inputsMeta__
    - Output specifications from spec.outputsMeta__
    - Application connector information for control setup
    - API endpoints from task specifications (not generic placeholders)

    ## CONTENT GENERATION GUIDELINES

    - Use realistic, system-specific examples that can be customized later
    - Include comments in code sections indicating customization points
    - Provide system-agnostic content that applies broadly
    - Use consistent naming conventions throughout all sections
    - Extract actual API documentation links from task specifications
    - Generate ValidationStatusCodes that are specific to the rule's compliance purpose
    - Ensure all sample data reflects the actual system being monitored

    ## WORKFLOW

    1. MCP retrieves rule context from stored rule information
    2. MCP generates complete Jupyter notebook using template structure above
    3. MCP populates template with extracted rule metadata and calculated values
    4. MCP returns complete notebook structure as dictionary for user review
    5. User reviews and confirms the structure
    6. If approved, call create_design_notes() to actually save the notebook

    ## ARGS

    - rule_name: Name of the rule for which to generate design notes preview

    ## RETURNS

    Dict containing complete notebook structure for user review and confirmation
    """
    
    # MCP should directly construct the design notes based on the instructions above
    # No intermediate API calls needed - MCP has all the template details in the docstring
    # The MCP will use fetch_rule() internally and build the complete notebook structure
    
    return {
        "success": True, 
        "rule_name": rule_name,
        "design_notes_structure": {},  # MCP will populate this with complete notebook dictionary
        "sections_count": 7,
        "message": f"MCP should construct complete notebook structure for rule '{rule_name}' based on the detailed template instructions above",
        "next_action": "MCP should use fetch_rule() and build complete notebook dictionary, then return it in design_notes_structure"
    }


@mcp.tool()
def create_design_notes(rule_name: str, design_notes_structure: dict[str, Any], ctx: Context | None = None) -> dict[str, Any]:
    """
    Create and save design notes after user confirmation.

    DESIGN NOTES CREATION:

    This tool actually creates and saves the design notes after the user has reviewed
    and confirmed the preview structure from generate_design_notes_preview().

    WORKFLOW:
    1. Before creating new design notes, call fetch_rule_design_notes() to check if already exist and continue the flow, if not then continue this flow
    2. User has already reviewed notebook structure from preview
    3. User confirmed the structure is acceptable
    4. This tool receives the complete design notes dictionary structure
    5. MCP saves the notebook and returns access details

    Args:
        rule_name: Name of the rule for which to create design notes
        design_notes_structure: Complete Jupyter notebook structure as dictionary

    Returns:
        Dict containing design notes creation status and access details
    """
    
    try:
        headers = wsutils.create_header(ctx)
        payload = {
            "ruleName": rule_name,
            "type": "mcp",
            "designNotesContent": rule.encode_content(design_notes_structure),  # Pass the complete notebook dictionary as an encoded string
        }
        
        save_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_SAVE_DESIGN_NOTES),
            data=json.dumps(payload),
            header=headers
        )

        message = save_resp.get("message")
        if isinstance(message, str) and message == "Design notes file created successfully.":
            return {
                "success": True,
                "rule_name": rule_name,
                "filename": f"{rule_name}.ipynb",
                "sections_saved": len(design_notes_structure.get("cells", [])),
                "message": f"Design notes successfully created and saved for rule '{rule_name}'"
            }
        else:
            return {
                "success": False,
                "error": "Failed to save design notes",
                "rule_name": rule_name
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to save design notes: {e}",
            "rule_name": rule_name
        }


@mcp.tool()
def generate_rule_readme_preview(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Generate README.md preview for rule documentation before actual creation.

    RULE README GENERATION:

    This tool generates a complete README.md structure as a string for user review.
    The MCP will create comprehensive rule documentation with detailed sections based on 
    rule context and metadata, then return it for user confirmation.

    README TEMPLATE STRUCTURE REQUIREMENTS:

    The MCP should generate a README.md with exactly these sections:

    ## SECTION 1: Rule Header
    DESCRIPTION: Rule identification and overview
    CONTENT REQUIREMENTS:
    - Rule name as main title (# {RULE_NAME})
    - Brief description from rule metadata
    - Status badges (Version, Application Type, Environment)
    - Purpose statement
    - Last updated timestamp
    FORMAT: Markdown header with badges and overview

    ## SECTION 2: Overview
    DESCRIPTION: High-level rule explanation
    CONTENT REQUIREMENTS:
    - What this rule does (purpose and description)
    - Target system/application
    - Compliance framework alignment
    - Key benefits and use cases
    - When to use this rule
    FORMAT: Markdown sections with bullet points

    ## SECTION 3: Rule Architecture
    DESCRIPTION: Technical architecture and flow
    CONTENT REQUIREMENTS:
    - Rule flow diagram (text-based)
    - Task sequence and dependencies
    - Data flow: Input → Processing → Output
    - Integration points
    - Architecture decisions
    FORMAT: Markdown with code blocks for diagrams

    ## SECTION 4: Inputs
    DESCRIPTION: Detailed input specifications
    CONTENT REQUIREMENTS:
    - Table of all rule inputs with:
      * Input Name
      * Data Type  
      * Required/Optional
      * Description
      * Default Value
      * Example Value
    - Input validation rules
    - File format specifications (for FILE inputs)
    FORMAT: Markdown table with detailed explanations

    ## SECTION 5: Tasks
    DESCRIPTION: Individual task breakdown
    CONTENT REQUIREMENTS:
    - For each task in the rule:
      * Task name and alias
      * Purpose and functionality
      * Input requirements
      * Output specifications
      * Processing logic overview
      * Error handling
    - Task execution order
    - Dependencies between tasks
    FORMAT: Markdown subsections for each task

    ## SECTION 6: Outputs
    DESCRIPTION: Rule output specifications
    CONTENT REQUIREMENTS:
    - Table of all rule outputs with:
      * Output Name
      * Data Type
      * Description
      * Format/Structure
      * Example Value
    - Output file formats and schemas
    - Success/failure indicators
    FORMAT: Markdown table with examples

    ## SECTION 7: Configuration
    DESCRIPTION: Rule configuration and setup
    CONTENT REQUIREMENTS:
    - Application type and environment settings
    - Execution level and mode
    - Required permissions and access
    - System prerequisites
    - Configuration examples
    - Environment-specific settings
    FORMAT: Markdown with code blocks

    ## SECTION 8: Usage Examples
    DESCRIPTION: Practical usage scenarios
    CONTENT REQUIREMENTS:
    - Basic usage example
    - Advanced configuration example
    - Common use cases
    - Best practices
    - Troubleshooting tips
    FORMAT: Markdown with code examples

    ## SECTION 9: I/O Mapping
    DESCRIPTION: Data flow mapping details
    CONTENT REQUIREMENTS:
    - Complete I/O mapping visualization
    - Rule input to task input mappings
    - Task output to task input mappings  
    - Task output to rule output mappings
    - Data transformation explanations
    FORMAT: Markdown with formatted mapping table

    ## SECTION 10: Troubleshooting
    DESCRIPTION: Common issues and solutions
    CONTENT REQUIREMENTS:
    - Common error scenarios
    - Input validation failures
    - Task execution errors
    - Output generation issues
    - Performance considerations
    - Support and contact information
    FORMAT: Markdown FAQ-style sections

    ## SECTION 11: Version History
    DESCRIPTION: Change log and versioning
    CONTENT REQUIREMENTS:
    - Current version information
    - Version history table
    - Change descriptions
    - Migration notes
    - Deprecation warnings
    FORMAT: Markdown table with version details

    ## SECTION 12: References
    DESCRIPTION: Additional resources and links
    CONTENT REQUIREMENTS:
    - Related documentation links
    - Compliance framework references
    - API documentation
    - Support resources
    - Contributing guidelines
    FORMAT: Markdown bullet list with links

    MARKDOWN FORMATTING REQUIREMENTS:
    - Use proper Markdown syntax
    - Include table of contents with links
    - Use code blocks for examples
    - Include badges and shields
    - Proper heading hierarchy (H1, H2, H3)
    - Use tables for structured data
    - Include horizontal rules for section separation

    MCP CONTENT POPULATION INSTRUCTIONS:
    The MCP should extract the following information from the rule context:
    - Rule name, purpose, description from rule metadata
    - System name from appType (clean by removing connector suffixes)
    - Task details from spec.tasks array (name, alias, purpose, appTags)
    - Input specifications from spec.inputs object
    - Output specifications from spec.outputsMeta__
    - I/O mappings from spec.ioMap array
    - Environment and execution settings from labels
    - Application type and integration details

    PLACEHOLDER REPLACEMENT RULES:
    - {RULE_NAME} = meta.name
    - {RULE_PURPOSE} = meta.purpose  
    - {RULE_DESCRIPTION} = meta.description
    - {SYSTEM_NAME} = extracted from appType
    - {VERSION} = meta.version or "1.0.0"
    - {ENVIRONMENT} = meta.labels.environment[0]
    - {APP_TYPE} = meta.labels.appType[0]
    - {EXEC_LEVEL} = meta.labels.execlevel[0]
    - {TASK_COUNT} = len(spec.tasks)
    - {INPUT_COUNT} = len(spec.inputs)
    - {OUTPUT_COUNT} = len(spec.outputsMeta__)
    - {TIMESTAMP} = current ISO timestamp

    CONTENT GUIDELINES:
    - Use clear, technical language
    - Include practical examples
    - Provide comprehensive coverage
    - Make it developer-friendly
    - Include troubleshooting help
    - Keep sections well-organized
    - Use consistent formatting

    WORKFLOW:
    1. MCP retrieves rule context using fetch_rule() 
       (ensure only the fetch_rule tool is called, not fetch_cc_rule)
    2. MCP extracts metadata and technical details
    3. MCP generates complete README.md content using template above
    4. MCP populates all placeholders with actual rule data
    5. MCP returns complete README content as string for user review
    6. User reviews and confirms the content
    7. If approved, call create_rule_readme() to actually save the README

    Args:
        rule_name: Name of the rule for which to generate README preview

    Returns:
        Dict containing complete README.md content as string for user review
    """
    
    # MCP should directly construct the README based on the instructions above
    # No intermediate API calls needed - MCP has all the template details in the docstring
    # The MCP will use fetch_rule() internally and build the complete README content
    
    return {
        "success": True, 
        "rule_name": rule_name,
        "readme_content": "",  # MCP will populate this with complete README.md content
        "sections_count": 12,
        "estimated_length": "2000-3000 lines",
        "message": f"MCP should construct complete README.md content for rule '{rule_name}' based on the detailed template instructions above",
        "next_action": "MCP should use fetch_rule() and build complete README markdown content, then return it in readme_content"
    }


@mcp.tool()
def create_rule_readme(rule_name: str, readme_content: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Create and save README.md file after user confirmation.

    README CREATION:

    This tool actually creates and saves the README.md file after the user has reviewed
    and confirmed the preview content from generate_rule_readme_preview().

    WORKFLOW:
    1. User has already reviewed README content from preview
    2. User confirmed the content is acceptable
    3. This tool receives the complete README.md content as string
    4. MCP saves the README file and returns access details

    Args:
        rule_name: Name of the rule for which to create README
        readme_content: Complete README.md content as string

    Returns:
        Dict containing README creation status and access details
    """
    
    try:
        headers = wsutils.create_header(ctx)
        payload = {
            "ruleName": rule_name,
            "type":"rule",
            "readmeContent": rule.encode_content(readme_content),  # Pass the complete README content as an encoded string
        }

        save_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_SAVE_RULE_README),
            data=json.dumps(payload),
            header=headers
        )

        message = save_resp.get("message")
        if isinstance(message, str) and message == "Read-me file created successfully.":
            return {
                "success": True,
                "rule_name": rule_name,
                "filename": "README.md",
                "content_length": len(readme_content),
                "sections_saved": readme_content.count("##"),  # Count markdown sections
                "message": f"README.md successfully created and saved for rule '{rule_name}'"
            }
        else:
            return {
                "success": False,
                "error": "Failed to save README.md",
                "rule_name": rule_name
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to save README.md: {e}",
            "rule_name": rule_name
        }


@mcp.tool()
def update_rule_readme(rule_name: str, updated_readme_content: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Update existing README.md file with new content.

    README UPDATE:

    This tool updates an existing README.md file with new content. Useful for
    making changes after initial creation or updating documentation as rules evolve.

    Args:
        rule_name: Name of the rule for which to update README
        updated_readme_content: Updated README.md content as string

    Returns:
        Dict containing README update status and details
    """
    
    try:
        headers = wsutils.create_header(ctx)
        payload = {
            "ruleName": rule_name,
            "type":"rule",
            "readmeContent": rule.encode_content(updated_readme_content),  # Pass the complete README content as an encoded string
        }
        update_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_SAVE_RULE_README),
            data=json.dumps(payload),
            header=headers
        )

        message = update_resp.get("message")
        if isinstance(message, str) and message == "Read-me file created successfully.":
            return {
                "success": True,
                "rule_name": rule_name,
                "filename": "README.md",
                "content_length": len(updated_readme_content),
                "message": f"README.md successfully updated for rule '{rule_name}'"
            }
        else:
            return {
                "success": False,
                "error": "Failed to update README.md",
                "rule_name": rule_name
            }
                     
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to update README.md: {e}",
            "rule_name": rule_name
        }


@mcp.tool()
def fetch_execution_progress(rule_name: str, execution_id: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Fetch execution progress for a running rule.
    
    IMPORTANT FOR CLAUDE/CLIENT:
    ================================
    This tool returns a snapshot of current progress. To see real-time updates:
    1. Call this tool repeatedly every 1 seconds
    2. Check the "continue_polling" flag in response
    3. If continue_polling=true, call again after 1 seconds
    4. If continue_polling=false, execution is complete
    
    DISPLAY INSTRUCTIONS FOR CLAUDE:
    ================================
    When displaying progress, REPLACE the previous output (don't append):
    
    🔄 **Execution Progress** (Live)
    ─────────────────────────────────
    
    Show each task on ONE line that UPDATES in place:
    • task_name (type) [progress_bar] XX% STATUS
    
    Use these Unicode blocks for progress bars:
    - COMPLETED: 🟦 (blue blocks)
    - INPROGRESS: 🟩 (green blocks) 
    - ERROR: 🟥 (red blocks)
    - PENDING: ⬜ (white blocks)
    
    After each poll, REPLACE the entire progress display with new data.
    DO NOT show multiple versions of the same task.
    
    EXAMPLE DISPLAY SEQUENCE:
    Poll 1:
    • fetch_users (HTTP) ⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0% PENDING
    • process_data (Script) ⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0% PENDING
    
    Poll 2 (REPLACES above):
    • fetch_users (HTTP) 🟩🟩🟩🟩⬜⬜⬜⬜⬜⬜ 40% INPROGRESS
    • process_data (Script) ⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0% PENDING
    
    Poll 3 (REPLACES above):
    • fetch_users (HTTP) 🟦🟦🟦🟦🟦🟦🟦🟦🟦🟦 100% COMPLETED
    • process_data (Script) 🟩🟩🟩⬜⬜⬜⬜⬜⬜⬜ 30% INPROGRESS
    
    RESPONSE FLAGS:
    - continue_polling: true = keep polling every 1 seconds
    - continue_polling: false = execution complete, show final summary
    - display_mode: "replace" = replace previous display
    
    UI DISPLAY REQUIREMENT:
    - The file URL must ALWAYS be displayed to the user in the UI, allowing the user to view or download the file directly.

    Args:
        rule_name: Rule being executed
        execution_id: ID from execute_rule()
        
    Returns:
        Dict with progress data and polling instructions
    """
    
    def consolidate_task_progress(progress_array):
        """Get latest state for each unique task from transaction history."""
        task_states = {}
        task_order = []
        
        for entry in progress_array:
            # Use taskId if available, otherwise use name as identifier
            task_id = entry.get("taskId") or entry.get("name", f"task_{len(task_states)}")
            
            if task_id not in task_order:
                task_order.append(task_id)
            
            # Update to latest state
            task_states[task_id] = {
                "id": task_id,
                "name": entry.get("name", "Unknown Task"),
                "type": entry.get("type", "Unknown"),
                "status": entry.get("status", "PENDING"),
                "progressPercentage": entry.get("progressPercentage", 0),
                "error": entry.get("error"),
                "outputs": entry.get("outputs")
            }
        
        return [task_states[tid] for tid in task_order]
    
    def create_progress_bar(percentage, status, bar_length=10):
        """Create a visual progress bar with colors."""
        filled = int((percentage / 100) * bar_length)
        empty = bar_length - filled
        
        # Use emoji blocks for universal color support
        if status == "COMPLETED":
            bar_char = "🟦"
        elif status == "INPROGRESS":
            bar_char = "🟩"
        elif status == "ERROR":
            bar_char = "🟥"
        else:  # PENDING
            bar_char = "⬜"
            filled = 0  # Show empty bar for pending
            empty = bar_length
        
        return bar_char * filled + "⬜" * empty
    
    try:
        header = wsutils.create_header(ctx)
        exec_payload = {"executionID": execution_id}
        
        # Fetch current progress
        exec_progress_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_FETCH_EXECUTION_PROGRESS),
            data=json.dumps(exec_payload),
            header=header
        )
        
        # Extract data
        overall_status = exec_progress_resp.get("status", "PENDING")
        task_summary = exec_progress_resp.get("taskProgressSummary", {})
        progress_array = exec_progress_resp.get("progress", [])
        
        # Consolidate tasks to current state
        consolidated_tasks = consolidate_task_progress(progress_array)
        
        # Create display data
        display_lines = []
        task_stats = {"COMPLETED": 0, "INPROGRESS": 0, "ERROR": 0, "PENDING": 0}
        
        for task in consolidated_tasks:
            status = task["status"]
            percentage = task["progressPercentage"]
            
            # Create progress bar
            progress_bar = create_progress_bar(percentage, status)
            
            # Format display line
            display_line = {
                "text": f"• {task['name']} ({task['type']}) {progress_bar} {percentage}% {status}",
                "task_name": task['name'],
                "task_type": task['type'],
                "progress_bar": progress_bar,
                "percentage": percentage,
                "status": status,
                "outputs": {
                    key : value for key, value in (task.get("outputs") or {}).items()
                    if key not in ["CompliancePCT_", "ComplianceStatus_"]
                } if task.get("outputs") else None
            }
            
            if status == "ERROR" and task.get("error"):
                display_line["error"] = task['error']
            
            display_lines.append(display_line)
            task_stats[status] = task_stats.get(status, 0) + 1
        
        # Determine if polling should continue
        continue_polling = overall_status not in ["COMPLETED", "ERROR"]
        
        # Create response
        response = {
            # Polling control
            "continue_polling": continue_polling,
            "polling_interval_seconds": 1,
            "display_mode": "replace",  # Tell client to replace, not append
            
            # Current state
            "status": overall_status,
            "rule_name": rule_name,
            "execution_id": execution_id,
            
            # Progress data
            "overall_progress_percentage": task_summary.get("progressPercentage", 0),
            "task_stats": {
                "completed": task_stats["COMPLETED"],
                "in_progress": task_stats["INPROGRESS"],
                "error": task_stats["ERROR"],
                "pending": task_stats["PENDING"],
                "total": len(consolidated_tasks)
            },
            
            # Display data
            "display_lines": display_lines,
            "display_header": f"🔄 **Execution Progress** - {rule_name}",
            "display_footer": f"Status: {overall_status} | Progress: {task_stats['COMPLETED']}/{len(consolidated_tasks)} tasks",
            
            # Metadata
            "transaction_count": len(progress_array),
            "unique_task_count": len(consolidated_tasks),
            "timestamp": exec_progress_resp.get("timestamp", "")
        }
        
        # Add completion data if finished
        if not continue_polling:
            response["completion_summary"] = {
                "final_status": overall_status,
                "total_tasks": len(consolidated_tasks),
                "successful_tasks": task_stats["COMPLETED"],
                "failed_tasks": task_stats["ERROR"]
            }
            response["display_header"] = f"✅ **Execution Complete** - {rule_name}" if overall_status == "COMPLETED" else f"❌ **Execution Failed** - {rule_name}"
        
        return response
        
    except Exception as e:
        return {
            "continue_polling": False,
            "status": "ERROR",
            "rule_name": rule_name,
            "execution_id": execution_id,
            "error": str(e),
            "display_header": "❌ **Error Fetching Progress**",
            "display_lines": [{"text": f"Error: {e}"}]
        }

@mcp.tool()
def fetch_output_file(file_url: str, ctx: Context | None = None) -> dict[str, Any]:
    """Fetch and display content of an output file from rule execution.

    FILE OUTPUT HANDLING:

    WHEN TO USE:
    - Rule execution output contains file URLs
    - User requests to view specific file content
    - Files contain reports, logs, compliance data, or analysis results

    CONTENT DISPLAY LOGIC:
    - If file size < 10KB: Show entire file content
    - If file size >= 10KB: Show only first 3 records/lines with user-friendly message
    - Supported formats: JSON, CSV, Parquet, and other text files
    - Always return file format extracted from filename
    - Provide clear user messaging about content truncation
    - CRITICAL: If content is truncated or full content, include truncation message with the display_content
    - The file URL (file_url) must ALWAYS be displayed to the user in the UI, allowing the user to view or download the file directly.
    
    MANDATORY CONTENT DISPLAY FORMAT:
    - FileName: [extracted from file_url]
    - Format: [file format from file_format]
    - Message: [truncation status or completion message if applicable user_message]  
    - Content: [display_content based on file format show the entire display_content]
    - File URL: [always show the file_url in the UI so the user can view or download the file]
    Args:
        file_url: URL of the file to fetch and display

    Returns:
        Dict containing file content, metadata, and display information
    """
    try:
        # Fetch file from API
        headers = wsutils.create_header(ctx)
        payload = {"fileURL": file_url}
        response = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_FETCH_FILE), 
            data=json.dumps(payload), 
            header=headers
        )

        file_content = response.get("fileContent", "")
        filename = response.get("fileName", "")
        
        # Get file format
        file_format = filename.split('.')[-1].lower() if '.' in filename else "unknown"
        if file_format == "pq": file_format = "parquet"

        # Decode content and calculate size
        try:
            if file_format == "parquet":
                actual_content = file_content  # Keep base64 for parquet
                file_size_bytes = len(base64.b64decode(file_content))
            else:
                actual_content = base64.b64decode(file_content).decode('utf-8')
                file_size_bytes = len(actual_content.encode('utf-8'))
        except:
            actual_content = file_content
            file_size_bytes = len(file_content.encode('utf-8'))

        file_size_kb = file_size_bytes / 1024
        
        # Process content - all preview functions now handle size logic internally
        if file_format == "parquet":
            display_content, info = rule.get_parquet_preview(actual_content, file_size_kb)
            user_message = f"📊 Parquet file ({file_size_kb:.2f}KB). {info}"
        elif file_format == "json":
            display_content, info = rule.get_json_preview(actual_content, file_size_kb)
            user_message = f"📄 JSON file ({file_size_kb:.2f}KB). {info}"
        elif file_format in ["csv", "tsv"]:
            display_content, info = rule.get_csv_preview(actual_content, file_size_kb)
            user_message = f"📊 {file_format.upper()} file ({file_size_kb:.2f}KB). {info}"
        else:
            # For other text files
            lines = actual_content.split('\n')
            # Determine preview size limit (in KB) from environment, defaulting to 10KB
            size_limit_kb = rule.get_file_preview_limit()
            if file_size_kb < size_limit_kb:
                display_content = actual_content
                user_message = f"✅ Complete file ({file_size_kb:.3f}KB)"
            else:
                display_content = '\n'.join(lines[:3])
                if len(lines) > 3:
                    display_content += "\n... (truncated)"
                user_message = f"📄 File ({file_size_kb:.2f}KB). Showing first 3 of {len(lines)} lines, You can download it using the link below."

        return {
            "success": True,
            "file_url": file_url,
            "filename": filename,
            "file_format": file_format,
            "file_size_kb": round(file_size_kb, 2),
            "display_content": display_content,
            "user_message": user_message
        }

    except Exception as e:
        return {
            "success": False,
            "file_url": file_url,
            "error": f"Failed to fetch file: {e}"
        }


@mcp.tool()
def prepare_applications_for_execution(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Analyze rule tasks and prepare application configuration requirements for execution.

    This tool helps users understand what applications are needed and whether they can
    share applications across multiple tasks.

    WHEN TO USE:
    - Before calling execute_rule() to understand application requirements
    - To identify if multiple tasks can share the same application
    - To determine if unique identifiers are needed when using different applications for same appType

    NOTE: This tool is optional. Rules with only 'nocredapp' tasks can be executed directly
    without any application configuration. Use this tool only when tasks require credentials.

    APPLICATION SHARING SCENARIOS (when applications are needed):
    1. **Shared Application**: User wants same credentials for all tasks of an appType
       - Single application config with basic appTags (just appType)
       - One application covers multiple tasks

    2. **Separate Applications**: User needs different credentials per task
       - Must add unique identifier key (e.g., "purpose") to task appTags
       - Each application config must include matching unique identifier

    3. **No Application Needed**: All tasks have 'nocredapp' appType
       - Skip application configuration entirely
       - Call execute_rule() with an empty applications list

    WORKFLOW:
    1. Call this tool with rule_name
    2. Review which tasks need applications (if any)
    3. If no tasks need applications (all nocredapp): Skip to step 6
    4. For tasks with same appType, decide: share or separate?
    5. If sharing: Provide one application config per appType
       If separate: Add unique identifiers and provide separate configs
    6. Call execute_rule() with configured applications (or empty list for nocredapp rules)

    Args:
        rule_name: Name of the rule to analyze

    Returns:
        Dict with analysis results and configuration guidance
    """
    try:
        # Fetch the rule
        rule_result = fetch_rule(rule_name, ctx)
        if not rule_result.get("success"):
            return {
                "success": False,
                "error": f"Could not fetch rule '{rule_name}': {rule_result.get('error')}"
            }
        
        rule_structure = rule_result.get("rule_structure", {})
        tasks = rule_structure.get("spec", {}).get("tasks", [])
        
        # Analyze tasks by appType
        app_type_tasks = {}  # {appType: [list of tasks]}
        tasks_needing_apps = []
        
        for task in tasks:
            app_tags = task.get("appTags", {})
            app_types = app_tags.get("appType", [])
            task_alias = task.get("alias", task.get("name", "unknown"))
            task_name = task.get("name", "unknown")
            
            for app_type in app_types:
                if app_type and app_type.lower() != "nocredapp":
                    if app_type not in app_type_tasks:
                        app_type_tasks[app_type] = []
                    
                    task_info = {
                        "task_name": task_name,
                        "task_alias": task_alias,
                        "app_tags": app_tags,
                        "has_unique_identifier": any(k not in ["appType", "environment", "execlevel"] for k in app_tags.keys())
                    }
                    app_type_tasks[app_type].append(task_info)
                    tasks_needing_apps.append(task_info)
        
        # Identify scenarios requiring differentiation
        needs_differentiation = {}
        for app_type, task_list in app_type_tasks.items():
            if len(task_list) > 1:
                # Multiple tasks share same appType - user needs to decide
                needs_differentiation[app_type] = {
                    "tasks": task_list,
                    "count": len(task_list),
                    "recommendation": "Ask user if they want to use the SAME application for all tasks or DIFFERENT applications"
                }
        
        # Build guidance
        guidance = []
        if needs_differentiation:
            guidance.append("⚠️ Multiple tasks share the same application type. You need to decide:")
            for app_type, info in needs_differentiation.items():
                task_names = [t["task_alias"] for t in info["tasks"]]
                guidance.append(f"  - {app_type}: Tasks {task_names}")
                guidance.append(f"    Option A: Use SAME application for all (shared credentials)")
                guidance.append(f"    Option B: Use DIFFERENT applications (requires unique identifiers)")
        
        # Determine if applications are needed
        applications_required = len(app_type_tasks) > 0

        # Build appropriate next steps and message
        if applications_required:
            next_steps = [
                "1. For each appType with multiple tasks, ask user: 'Share same application or use different applications?'",
                "2. If DIFFERENT: Call add_unique_identifier_to_task() for each task",
                "3. Then configure applications with matching identifiers",
                "4. Call execute_rule() with the configured applications"
            ]
            message = f"Analysis complete. Found {len(app_type_tasks)} application types across {len(tasks_needing_apps)} tasks."
        else:
            next_steps = [
                "1. No application configuration needed - all tasks use 'nocredapp'",
                "2. Call execute_rule() directly with an empty applications list"
            ]
            message = "Analysis complete. No application configuration required - all tasks use 'nocredapp'. You can execute the rule directly."
            guidance.append("✅ No application configuration needed - all tasks use 'nocredapp' appType.")

        return {
            "success": True,
            "rule_name": rule_name,
            "app_type_tasks": app_type_tasks,
            "tasks_needing_apps": tasks_needing_apps,
            "needs_differentiation": needs_differentiation,
            "total_app_types": len(app_type_tasks),
            "applications_required": applications_required,
            "guidance": guidance,
            "next_steps": next_steps,
            "message": message
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to analyze rule: {str(e)}"
        }


@mcp.tool()
def add_unique_identifier_to_task(rule_name: str, task_alias: str, identifier_key: str, identifier_value: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Add a unique identifier key-value pair to a specific task's appTags.

    Use this when multiple tasks share the same appType but need DIFFERENT applications.
    The unique identifier allows the system to match each application to its specific task.

    WHEN TO USE:
    - After prepare_applications_for_execution() identifies tasks needing differentiation
    - When user chooses "separate applications" option for tasks with same appType
    - Before configuring separate applications for same appType tasks

    NOT NEEDED WHEN:
    - User wants to SHARE the same application across multiple tasks
    - Task already has a unique appType (no other tasks share it)

    WORKFLOW:
    1. Call prepare_applications_for_execution() 
    2. If user chooses separate applications for an appType:
       - Call this tool for each task to add unique identifier
       - Use same key but different values (e.g., "purpose": "source" vs "purpose": "target")
    3. Configure applications with matching identifiers

    Args:
        rule_name: Name of the rule containing the task
        task_alias: Alias of the task to update
        identifier_key: Unique identifier key (e.g., "purpose", "sourceSystem")
        identifier_value: Value for the identifier (e.g., "source-repo", "production-db")
        
    Returns:
        Dict with update status and guidance
    """
    try:
        # Fetch the rule
        rule_result = fetch_rule(rule_name, ctx)
        if not rule_result.get("success"):
            return {
                "success": False,
                "error": f"Could not fetch rule '{rule_name}': {rule_result.get('error')}"
            }
        
        rule_structure = rule_result.get("rule_structure", {})
        tasks = rule_structure.get("spec", {}).get("tasks", [])
        
        # Find and update the task
        task_found = False
        updated_task = None
        for task in tasks:
            if task.get("alias") == task_alias or task.get("name") == task_alias or task.get("aliasref") == task_alias:
                task_found = True
                
                # Initialize appTags if not present
                if "appTags" not in task:
                    task["appTags"] = {}
                
                # Add the unique identifier as an array (consistent with other appTags)
                task["appTags"][identifier_key] = [identifier_value]
                updated_task = task
                break
        
        if not task_found:
            return {
                "success": False,
                "error": f"Task with alias '{task_alias}' not found in rule '{rule_name}'"
            }
        
        # Update the rule
        rule_structure["spec"]["tasks"] = tasks
        
        # Also update rule-level labels if this is the primary app type
        primary_app_types = rule_structure.get("meta", {}).get("labels", {}).get("appType", [])
        task_app_types = updated_task.get("appTags", {}).get("appType", [])
        
        if any(at in primary_app_types for at in task_app_types):
            # This task's appType matches primary - update rule labels too
            if "labels" not in rule_structure.get("meta", {}):
                rule_structure["meta"]["labels"] = {}
            rule_structure["meta"]["labels"][identifier_key] = [identifier_value]
        
        # Save the updated rule
        if constants.ENABLE_RULE_CREATION_TASK_CHAIN_PROCESS:
            update_result = create_rule(rule_structure, True, ctx)
        else:
            update_result = create_rule(rule_structure, ctx)
        
        if not update_result.get("success"):
            return {
                "success": False,
                "error": f"Failed to update rule: {update_result.get('error')}"
            }
        
        return {
            "success": True,
            "rule_name": rule_name,
            "task_alias": task_alias,
            "identifier_added": {
                "key": identifier_key,
                "value": identifier_value
            },
            "updated_app_tags": updated_task.get("appTags", {}),
            "message": f"Added '{identifier_key}': ['{identifier_value}'] to task '{task_alias}'",
            "next_step": f"When configuring application for this task, include '{identifier_key}': ['{identifier_value}'] in appTags",
            "application_config_example": {
                "applicationType": "<application_class_name>",
                "applicationId": "<app_id> OR provide credentials",
                "appTags": {
                    "appType": task_app_types,
                    identifier_key: [identifier_value]
                }
            }
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to add unique identifier: {str(e)}"
        }


def create_initial_rule_from_planning(rule_name: str, purpose: str, description: str, selected_tasks: list[dict], primary_app_type: str = None) -> dict[str, Any]:
    """
    Create initial rule structure after planning confirmation.
    This builds a rule with tasks but empty inputs - will be auto-detected as DRAFT status.
    
    This function is called internally after user confirms the input overview.
    """
    
    # Determine primary app type from tasks if not provided
    if not primary_app_type:
        app_types = []
        for task_info in selected_tasks:
            task_details = get_task_details(task_info["task_name"], None)  # No context available in this helper function
            if task_details.get("appTags", {}).get("appType"):
                app_types.extend(task_details["appTags"]["appType"])
        unique_app_types = list(set([t for t in app_types if t != "nocredapp"]))
        primary_app_type = unique_app_types[0] if unique_app_types else "generic"

    # Build initial rule structure with tasks but no inputs
    initial_rule_structure = {
        "apiVersion": "rule.policycow.live/v1alpha1",
        "kind": "rule",
        "meta": {
            "name": rule_name,
            "purpose": purpose,
            "description": description,
            # No explicit status - will be auto-detected as DRAFT
            "labels": {
                "appType": [primary_app_type],
                "environment": ["logical"],
                "execlevel": ["app"]
            },
            "annotations": {
                "annotateType": [primary_app_type],
                "app": [primary_app_type]
            }
        },
        "spec": {
            "inputs": {},  # Empty - will cause DRAFT status detection
            "inputsMeta__": [],  # Empty initially
            "outputsMeta__": [
                {"name": "CompliancePCT_", "dataType": "FLOAT", "required": True, "defaultValue": 0.0},
                {"name": "ComplianceStatus_", "dataType": "STRING", "required": True, "defaultValue": "NOT_DETERMINED"},
                {"name": "LogFile", "dataType": "FILE", "required": True, "defaultValue": ""}
            ],
            "tasks": [
                {
                    "name": task_info["task_name"],
                    "alias": task_info["task_alias"],
                    "type": "task",
                    "appTags": get_task_details(task_info["task_name"], None).get("appTags", {}),  # No context available in this helper function
                    "purpose": task_info.get("purpose", f"Task {task_info['task_alias']}")
                }
                for task_info in selected_tasks
            ],
            "ioMap": []  # Empty - rule not ready yet
        }
    }
    
    # Create rule - status will be auto-detected as DRAFT
    return create_rule(initial_rule_structure)

def finalize_rule_with_io_mapping(rule_name: str, task_input_mapping: dict = None, ctx: Context | None = None) -> dict[str, Any]:
    """
    Finalize rule by adding I/O mapping and setting status to ACTIVE.
    Called internally after user confirms input verification.
    
    This function builds the complete I/O mapping based on task sequence and collected inputs.
    """
    
    try:
        # Fetch current rule
        current_rule = fetch_rule(rule_name, ctx)
        if not current_rule["success"]:
            return {"success": False, "error": f"Rule '{rule_name}' not found"}
        
        rule_structure = current_rule["rule_structure"]
        
        # Build I/O mapping from existing rule structure
        tasks = rule_structure["spec"]["tasks"]
        inputs = rule_structure["spec"]["inputs"]
        
        io_map = []
        
        if tasks and inputs:
            # Rule inputs to first task inputs
            if len(tasks) > 0:
                first_task_alias = tasks[0]["alias"]
                for input_name in inputs.keys():
                    # Use task_input_mapping if provided for precise mapping
                    if task_input_mapping and input_name in task_input_mapping:
                        original_input_name = task_input_mapping[input_name]["input_name"]
                        io_map.append(f"{first_task_alias}.Input.{original_input_name}:=*.Input.{input_name}")
                    else:
                        # Generic mapping
                        io_map.append(f"{first_task_alias}.Input.InputData:=*.Input.{input_name}")
            
            # Sequential task-to-task flow
            for i in range(len(tasks) - 1):
                current_alias = tasks[i]["alias"]
                next_alias = tasks[i + 1]["alias"]
                io_map.append(f"{next_alias}.Input.InputData:={current_alias}.Output.OutputData")
            
            # Final outputs from last task (mandatory compliance outputs)
            if len(tasks) > 0:
                last_alias = tasks[-1]["alias"]
                io_map.extend([
                    f"'*.Output.CompliancePCT_:={last_alias}.Output.CompliancePCT_'",
                    f"'*.Output.ComplianceStatus_:={last_alias}.Output.ComplianceStatus_'",
                    f"'*.Output.LogFile:={last_alias}.Output.LogFile'"
                ])
        
        # Add I/O mapping to rule
        rule_structure["spec"]["ioMap"] = io_map
        
        # Update rule - status will be auto-detected as ACTIVE
        return create_rule(rule_structure, ctx)
        
    except Exception as e:
        return {"success": False, "error": f"Failed to finalize rule: {e}"}

def determine_next_steps(creation_phase: str, completion_analysis: dict) -> list[str]:
    """Helper function to determine next steps based on current phase."""
    
    if creation_phase == "completed":
        return ["execute_rule", "create_design_notes", "create_readme"]
    elif creation_phase == "inputs_collected":
        return ["build_io_mapping", "finalize_rule"]
    elif creation_phase == "collecting_inputs":
        return ["continue_input_collection", "collect_remaining_inputs"]
    elif creation_phase == "tasks_selected":
        return ["prepare_input_overview", "start_input_collection"]
    elif creation_phase == "initialized":
        return ["select_tasks", "define_task_aliases"]
    else:
        return ["review_rule_structure", "check_requirements"]


def determine_next_action(creation_phase: str, completion_analysis: dict) -> str:
    """Helper function to determine the immediate next action."""
    
    if creation_phase == "completed":
        return "Call create_design_notes() to auto-generate comprehensive design notes. Call create_rule_readme() to auto-generate a comprehensive README file."
    elif creation_phase == "inputs_collected":
        return "Call finalize_rule_with_io_mapping() to build I/O mapping and complete rule creation."
    elif creation_phase == "collecting_inputs":
        return "Continue collecting remaining inputs using collect_template_input() or collect_parameter_input()."
    elif creation_phase == "tasks_selected":
        return "Call prepare_input_collection_overview() to analyze input requirements and start collection."
    elif creation_phase == "initialized":
        return "Select tasks and define task aliases, then call prepare_input_collection_overview()."
    else:
        return "Review rule requirements and current state to determine next steps."


def estimate_completion_time(completion_analysis: dict) -> str:
    """Helper function to estimate time to completion."""
    
    if completion_analysis.get("has_io_mapping"):
        return "Complete"
    elif completion_analysis.get("has_inputs"):
        return "~5 minutes"

def validate_input_name(input_name: str) -> str:
    """Ensure input names contain only alphanumeric characters and underscores"""
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', input_name):
        # Replace invalid characters with underscores
        cleaned_name = re.sub(r'[^a-zA-Z0-9_]', '_', input_name)
        return cleaned_name
    return input_name


def is_valid_uuid(value: str) -> bool:
    """
    Check if the given string is a valid UUID.

    Args:
        value (str): The string to validate.

    Returns:
        bool: True if the string is a valid UUID, otherwise False.
    """
    try:
        uuid_obj = uuid.UUID(str(value))
        return str(uuid_obj) == value.lower()
    except (ValueError, TypeError, AttributeError):
        return False

def validate_application(selected_application: dict, cc_application: dict):
    """
    Validates that the user-selected application matches the stored ComplianceCow application.

    Checks:
        - applicationId matches the record ID.
        - appTags and othersTags have matching keys and values (case-insensitive).
        - Identifies missing, extra, or mismatched tags.
        - Supports unique identifier matching for multi-application scenarios.

    Returns:
        (bool, dict):
            - bool: True if valid, False otherwise.
            - dict: Details of differences and a reconfiguration message if invalid.
    """

    if selected_application.get("applicationId") != cc_application.get("id"):
        return False, {
            "error": "The provided applicationId does not match the selected application. Please try again with a valid application ID."
        }

    result = {
        "missingInOthersTags": [],
        "extraInOthersTags": [],
        "mismatchedValues": []
    }
    is_valid = True
    app_tags = selected_application.get("appTags", {})
    others_tags = cc_application.get("othersTags", {})
    
    # Normalize all keys and values to lowercase for comparison
    app_tags_normalized = {k.lower(): sorted([v.lower() for v in vals]) for k, vals in app_tags.items()}
    others_tags_normalized = {k.lower(): sorted([v.lower() for v in vals]) for k, vals in others_tags.items()}

    # Define standard tags that don't need strict matching
    standard_tags = ["apptype", "environment", "execlevel"]
    
    # Check missing keys (excluding standard tags - those are handled separately)
    for key in app_tags_normalized:
        if key not in standard_tags and key not in others_tags_normalized:
            is_valid = False
            result["missingInOthersTags"].append(key)

    # Check extra keys (informational only - not a failure)
    for key in others_tags_normalized:
        if key not in app_tags_normalized and key not in standard_tags:
            # Extra tags in the application are OK - just informational
            result["extraInOthersTags"].append(key)

    # Check mismatched values for common keys (excluding standard tags)
    for key in app_tags_normalized:
        if key in others_tags_normalized and key not in standard_tags:
            if app_tags_normalized[key] != others_tags_normalized[key]:
                is_valid = False
                result["mismatchedValues"].append({
                    "key": key,
                    "expected": app_tags_normalized[key],
                    "found": others_tags_normalized[key]
                })
    
    if not is_valid:
        result["reconfigure"] = "Reconfigure the application and rule structure, then try again."
        result["hint"] = "Ensure the unique identifier tags in your application config match those in the task's appTags."

    return is_valid, result

# @mcp.prompt()
def alterntive_prompt() -> str:
    return "When generating the JQ expression, do not hard-code any values from the previous task’s output. If your requirement involves comparing or merging two files, use ExecuteSqlQueryV2 instead."

if constants.ENABLE_RULE_CREATION_TASK_CHAIN_PROCESS:
    @mcp.tool()
    def create_rule(rule_structure: dict[str, Any], is_update: bool, ctx: Context | None = None) -> dict[str, Any]:
        """Create a rule with the provided structure.

        COMPLETE RULE CREATION PROCESS WITH PROGRESSIVE SAVING:

        This tool now handles both initial rule creation and progressive updates during the rule creation workflow.
        It intelligently detects the completion status and sets appropriate metadata automatically.
        It returns the URL to view the rule in the UI once it is created display the URL in chat.

        ENHANCED FOR PROGRESSIVE SAVING:
        - Automatically detects rule completion status based on rule structure content
        - Determines if rule is in-progress, ready for execution, or needs more inputs
        - Handles both initial creation and updates of existing rules
        - No additional parameters needed - analyzes rule structure intelligently
        - Maintains all existing validation and creation logic
        - Preserves all original docstring instructions and requirements

        CRITICAL REQUIREMENT - INPUTS META:
        - `spec.inputsMeta__` is **mandatory** for all rules, and rule creation cannot proceed without it.

        AUTOMATIC STATUS DETECTION:
        - DRAFT: Rule has tasks but missing inputs or I/O mapping (5-85% complete)
        - READY_FOR_CREATION: All inputs collected but I/O mapping incomplete (85% complete)
        - ACTIVE: Complete rule with tasks, inputs, and I/O mapping (100% complete)

        RULE COMPLETION ANALYSIS:
        - Checks if tasks are defined in spec.tasks
        - Validates that `spec.inputsMeta__` exists
        - Counts collected inputs in spec.inputs vs spec.inputsMeta__
        - Validates I/O mapping presence and completeness in spec.ioMap
        - Analyzes outputsMeta__ for mandatory compliance outputs
        - Sets appropriate status and creation phase automatically

        PROGRESSIVE CREATION PHASES (Auto-detected):
        1. "initialized" - Basic rule info provided (5%)
        2. "tasks_selected" - Tasks chosen and defined (25%) 
        3. "collecting_inputs" - Individual inputs being collected (25-85%)
        4. "inputs_collected" - All inputs gathered, ready for I/O mapping (85%)
        5. "completed" - Final rule creation complete with I/O mapping (100%)

        ORIGINAL REQUIREMENTS MAINTAINED:
        - All existing validation rules still apply
        - Task alias validation in I/O mappings preserved
        - Primary app type determination logic maintained
        - Mandatory output requirements (CompliancePCT_, ComplianceStatus_, LogFile)
        - YAML preview and user confirmation workflow preserved
        - All existing error handling and validation checks

        CRITICAL: This tool should be called:
        1. After planning phase to create initial rule structure
        2. After each input collection to update rule progressively
        3. After input verification to finalize rule with I/O mapping
        4. Rule status and progress automatically detected each time
        5. **When the user selects “Customize the existing rule”, the system must immediately execute the existing rule before allowing any modifications.
            This execution must occur automatically and without requesting user confirmation.
            However, the system must collect all required inputs from the user that are necessary to run this execution.
            After execution is complete, all customizations—including adding new tasks, modifying task order, or updating input values—must be applied on top of the freshly executed rule output, 
            ensuring the user always customizes the most up-to-date version of the rule.**

        PRE-CREATION REQUIREMENTS (Original):
        1. `spec.inputsMeta__` must be defined and contain valid input definitions
        2. All inputs must be collected through systematic workflow
        3. User must provide input overview confirmation  
        4. All template inputs processed via collect_template_input()
        5. All parameter values collected and verified
        6. User must confirm all input values before rule creation
        7. Primary application type must be determined
        8. Rule structure must be shown to user in YAML format for final approval

        STEP 1 - PRIMARY APPLICATION TYPE DETERMINATION (Preserved):
        Before creating rule structure, determine primary application type:
        1. Collect all unique appType tags from selected tasks
        2. Filter out 'nocredapp' (dummy placeholder value)
        3. Handle app type selection:
            - If only one valid appType: Use automatically
            - If multiple valid appTypes: Ask user to choose primary application
            - If no valid appTypes (all were nocredapp): Use 'generic' as default
        4. Set primary app type for appType, annotateType, and app fields (single value arrays)

        STEP 2 - RULE STRUCTURE WITH TASK ALIASES (Preserved):
        ```yaml
            apiVersion: rule.policycow.live/v1alpha1
            kind: rule
            meta:
                name: MeaningfulRuleName — Use a simple, clean name with no spaces or special characters.
                purpose: Clear, concise statement that reflects the user’s intended outcome. 
                description: A detailed explanation combining all task steps into a coherent narrative. 
                labels:
                    appType: [PRIMARY_APP_TYPE_FROM_STEP_1] # Single value array CRITICAL: Must be extracted from spec.tasks[].appTags.appType - NEVER use random values or user requirements
                    environment: [logical] # Array
                    execlevel: [app] # Array
                annotations:
                    annotateType: [PRIMARY_APP_TYPE_FROM_STEP_1] # Same as appType - MUST match a task's appType
            spec:
                inputs:
                InputName: [ACTUAL_USER_VALUE_OR_FILE_URL]  # Use original or unique names based on conflicts, omit duplicates
                inputsMeta__:
                - name: InputName             # unique name for the input
                description:                # purpose of the input
                dataType: FILE|HTTP_CONFIG|STRING|INT|FLOAT|BOOLEAN|DATE|DATETIME
                repeated:                   # true = multiple values allowed, false = single value
                allowedValues:              # if repeated=true: comma-separated input is split into array
                required:                   # value must be taken from task details.
                defaultValue: [ACTUAL_USER_VALUE] #values are collected from users, If the dataType is FILE or HTTP_CONFIG then the value should be filepath URL.
                format: [ACTUAL_FILE_FORMAT]      # only include for FILE types (json, yaml, toml, xml, etc.)
                showField: true                   # true = most important field, false = optional/less important
                outputsMeta__:
                - name: FinalOutput
                dataType: FILE|STRING|INT|FLOAT|BOOLEAN|DATE|DATETIME
                required: true
                defaultValue: [ACTUAL_RULE_OUTPUT_VALUE]
                tasks:
                - name: Step1TaskName # Original task names
                alias: step1 # Meaningful task aliases (simple descriptors)
                type: task
                appTags:
                    appType: [COPY_FROM_TASK_DEFINITION] # Keep original task appType
                    environment: [logical] # Array
                    execlevel: [app] # Array
                purpose: What this task does for Step 1
                - name: Step2TaskName
                alias: validation # Another meaningful alias
                type: task
                appTags:
                    appType: [COPY_FROM_TASK_DEFINITION]
                    environment: [logical] # Array
                    execlevel: [app] # Array
                purpose: What this task does for validation
                ioMap:
                - step1.Input.TaskInput:=*.Input.InputName  # Use task aliases in I/O mapping
                - validation.Input.TaskInput:=step1.Output.TaskOutput
                # MANDATORY: Always include these three outputs from the last task
                - '*.Output.FinalOutput:=validation.Output.TaskOutput'
                - '*.Output.CompliancePCT_:=validation.Output.CompliancePCT_'    # Compliance percentage from last task
                - '*.Output.ComplianceStatus_:=validation.Output.ComplianceStatus_'  # Compliance status from last task
                - '*.Output.LogFile:=validation.Output.LogFile'  # Log file from last task
        ```

        STEP 3 - I/O MAPPING WITH TASK ALIASES (Preserved):
        - Use golang-style assignment: destination:=source
        - 3-part structure: PLACE.DIRECTION.ATTRIBUTE_NAME
        - Always use EXACT attribute names from task specifications
        - Use meaningful task aliases instead of generic names
        - Ensure sequential data flow: Rule → Task1 → Task2 → Rule
        - Mandatory compliance outputs from last task

        STEP 4 - inputsMeta__ Cleanup:
        In spec.inputsMeta__, retain only the entries whose keys exist in spec.inputs. Remove any fields in spec.inputsMeta__ that are not present in spec.inputs.

        VALIDATION CHECKLIST (Preserved):
        □ Rule structure validation against schema
        □ Task alias validation in I/O mappings
        □ Primary app type determination
        □ Input/output specifications validation
        □ Mandatory compliance outputs present
        □ Sequential data flow in I/O mappings

        Args:
            rule_structure: Complete rule structure with any level of completion

        Returns:
            Result of rule creation including auto-detected status and completion level
        """
        logger.debug("------------- called create_rule -------------")
        logger.debug(f"rule_structure ::: {rule_structure}")
        logger.debug(f"is_update ::: {is_update}")
        try:
            if rule.is_valid_key(rule_structure,"spec") and  rule.is_valid_array(rule_structure["spec"],"tasks"):
                tasks = rule_structure["spec"]["tasks"]
                for task in tasks:
                    if rule.is_valid_key(task,"aliasref") and not rule.is_valid_key(task,"alias"):
                        task["alias"] = task["aliasref"]
                rule_structure["spec"]["tasks"] = tasks
            # Validate rule structure (preserve original validation)
            validation_result = rule.validate_rule_structure(rule_structure)
            if not validation_result["valid"]:
                return {"success": False, "error": "Invalid rule structure", "validation_errors": validation_result["errors"]}

            # Additional validation for task aliases in I/O mappings (preserved from original)
            tasks_section = rule_structure.get("spec", {}).get("tasks", [])
            io_map = rule_structure.get("spec", {}).get("ioMap", [])
            
            # Extract task aliases from tasks section for validation
            valid_aliases = set()
            for task in tasks_section:
                if "alias" in task:
                    valid_aliases.add(task["alias"])
            
            # Validate I/O mappings use correct task aliases (preserved validation)
            io_mapping_errors = []
            for mapping in io_map:
                if "." in mapping and ":=" in mapping:
                    left_side = mapping.split(":=")[0].strip()
                    right_side = mapping.split(":=")[1].strip()
                    
                    # Check left side for task alias
                    if not left_side.startswith("*."):
                        alias_part = left_side.split(".")[0]
                        if alias_part not in valid_aliases and alias_part != "*":
                            return {
                                "success": False,
                                "error": f"Unknown task alias '{alias_part}' in I/O mapping: {mapping}. Valid aliases: {list(valid_aliases)}"
                            }
                    
                    # Check right side for task alias  
                    if not right_side.startswith("*."):
                        alias_part = right_side.split(".")[0]
                        if alias_part not in valid_aliases and alias_part != "*":
                            return {
                                "success": False,
                                "error": f"Unknown task alias '{alias_part}' in I/O mapping: {mapping}. Valid aliases: {list(valid_aliases)}"
                            }

                    # Validate right side (source) output exists in task
                    if not right_side.startswith("*."):
                        parts = right_side.split(".")
                        if len(parts) >= 3:  # task_alias.Output.output_name format
                            source_task_alias = parts[0]
                            direction = parts[1]
                            output_name = parts[2]
                            
                            if direction == "Output":
                                # Find the task with this alias
                                source_task = None
                                for task in tasks_section:
                                    if task.get("alias") == source_task_alias:
                                        source_task = task
                                        break
                                
                                if source_task:
                                    # Get task details to validate output exists
                                    task_name = source_task.get("name")
                                    task_details= get_task_details(task_name, ctx)
                                    if task_details.get("error"):
                                        io_mapping_errors.append(f"Could not validate task '{task_name}': {task_details['error']}")
                                    else:
                                        # Check if the output exists in task definition
                                        task_outputs = task_details.get("outputs", [])
                                        valid_output_names = [out["name"] for out in task_outputs]
                                        
                                        if output_name not in valid_output_names:
                                            io_mapping_errors.append(
                                                f"Output '{output_name}' not found in task '{task_name}'. "
                                                f"Valid outputs: {valid_output_names}"
                                            )  

            # Return validation errors if any I/O mapping issues found
            if io_mapping_errors:
                return {
                    "success": False,
                    "error": "I/O mapping validation failed",
                    "validation_errors": io_mapping_errors,
                    "message": "Some I/O mappings reference outputs that don't exist in the specified tasks"
                }    

            # NEW: AUTOMATIC STATUS DETECTION based on rule content
            spec = rule_structure.get("spec", {})
            meta = rule_structure.get("meta", {})

            # MANDATORY: Fetch application class name for the primary app type
            primary_app_type_array = meta.get("labels", {}).get("appType", [])
            primary_app_type = primary_app_type_array[0] if primary_app_type_array else None
            applications_response = fetch_applications(ctx)
            application_class_name = None

            # Find matching application class name for primary app type
            if applications_response and applications_response.get("success") and primary_app_type:
                for app in applications_response.get("applications"):
                    app_type = app.get("app_type")
                    # Check if any app type from primary_app_type matches any app type from the application
                    if app_type == primary_app_type:
                        application_class_name = app.get("application_class_name")
                        break
                # Add app    
                rule_structure["meta"]["app"] = application_class_name     
            
            
            
            # Analyze rule completeness for auto-detection
            tasks = spec.get("tasks", [])
            inputs = spec.get("inputs", {})
            inputs_meta = spec.get("inputsMeta__", [])
            io_map = spec.get("ioMap", [])
            outputs_meta = spec.get("outputsMeta__", [])
            
            # Check for mandatory compliance outputs
            mandatory_outputs = ["CompliancePCT_", "ComplianceStatus_", "LogFile"]
            has_mandatory_outputs = all(
                any(output.get("name") == req_output for output in outputs_meta) 
                for req_output in mandatory_outputs
            )
            
            # Completion analysis
            completion_analysis = {
                "has_tasks": len(tasks) > 0,
                "has_inputs": len(inputs) > 0 and any(
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                    for value in inputs.values()
                ),
                "has_inputs_meta": len(inputs_meta) > 0,
                "has_io_mapping": len(io_map) > 0,
                "has_mandatory_outputs": has_mandatory_outputs,
                "tasks_count": len(tasks),
                "inputs_collected": sum(1 for value in inputs.values() if (
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                )),
                "inputs_meta_count": len(inputs_meta),
                "io_mappings_count": len(io_map),
                "inputs_match_metadata": len(inputs) == len(inputs_meta),
                "total_inputs_needed": len(inputs_meta),  # Total inputs from inputsMeta__
                "inputs_completion_percentage": (sum(1 for value in inputs.values() if (
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                )) / max(len(inputs_meta), 1)) * 100 if inputs_meta else 0
            }
            
            # Enhanced automatic status determination
            if (completion_analysis["has_io_mapping"] and 
                completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"] and  # All inputsMeta__ inputs collected
                completion_analysis["has_tasks"] and
                completion_analysis["has_mandatory_outputs"] and
                completion_analysis["inputs_match_metadata"]):
                auto_status = "ACTIVE"
                creation_phase = "completed"
                progress_percentage = 100
                
            elif (completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"] and  # All inputsMeta__ inputs collected
                completion_analysis["has_tasks"] and
                completion_analysis["has_mandatory_outputs"] and
                completion_analysis["inputs_match_metadata"]):
                auto_status = "READY_FOR_CREATION"  
                creation_phase = "inputs_collected"
                progress_percentage = 85
                
            elif completion_analysis["has_tasks"]:
                if completion_analysis["inputs_collected"] > 0:  # Some inputs have values
                    auto_status = "DRAFT"
                    creation_phase = "collecting_inputs"
                    # Calculate progress: 25% base + (input completion percentage * 0.6)
                    progress_percentage = min(25 + int(completion_analysis["inputs_completion_percentage"] * 0.6), 85)
                else:
                    auto_status = "DRAFT"
                    creation_phase = "tasks_selected"
                    progress_percentage = 25
            else:
                auto_status = "DRAFT"
                creation_phase = "initialized"
                progress_percentage = 5

            # Set detected status in meta (don't override if explicitly provided and valid)
            if "status" not in meta or meta["status"] not in ["DRAFT", "READY_FOR_CREATION", "ACTIVE"]:
                rule_structure["meta"]["status"] = auto_status
            if "creation_phase" not in meta:
                rule_structure["meta"]["creation_phase"] = creation_phase

            # Add automatic timestamps (preserve existing if present)
            current_time = datetime.now().isoformat()
            if "created_at" not in meta:
                rule_structure["meta"]["created_at"] = current_time
            rule_structure["meta"]["last_updated"] = current_time

            # Add/update progress tracking with detailed analysis
            rule_structure["meta"]["progress"] = {
                "percentage": progress_percentage,
                "phase": creation_phase,
                "completion_analysis": completion_analysis,
                "next_steps": determine_next_steps(creation_phase, completion_analysis),
                "estimated_completion": estimate_completion_time(completion_analysis)
            }

            # Check if rule already exists (for updates vs creation)
            # existing_rule = fetch_rule(rule_structure["meta"]["name"], ctx)
            # is_update = existing_rule["success"]

            # Generate YAML preview for user confirmation (preserved from original)
            yaml_preview = rule.generate_yaml_preview(rule_structure)

            # Call your existing create_rule_api (preserved)
            if not is_update:
                result = rule.create_rule_api(rule_structure, ctx)
            else:
                result = rule.update_rule_api(rule_structure,ctx)

            # Auto-generate design notes info (preserved from original)
            design_notes_result = {
                "auto_generated": True, 
                "message": "Design notes will be auto-generated using comprehensive internal template",
                "next_action": "Call create_design_notes(rule_name, design_notes_structure) to generate and save design notes"
            }

            readme_info = {
                "auto_generated": True, 
                "message": "README will be auto-generated using a comprehensive internal template",
                "next_action": "Call create_rule_readme(rule_name, readme_content) to generate and save the README"
            }
            
            rule_name = rule_structure["meta"]["name"]

            # Build UI URL
            base_host = constants.host.rstrip("/api") if hasattr(constants, "host") and isinstance(constants.host, str) else getattr(constants, "host", "")
            ui_url = f"{base_host}/ui/create-pc-rule?name={rule_name}&catalog=localcatalog" if base_host else ""
                
            #Add MCP tag to the rule with proper error handling
            try:
                tag_result = add_rule_tag(rule_name, ctx)
                if not tag_result.get("success", False):
                    tag_message = tag_result.get("message", "Unknown error occurred")
                    tag_status = {
                        "tagged": False,
                        "message": f"Rule created successfully but MCP tag addition failed: {tag_message}"
                    }
                else:
                    tag_status = {
                        "tagged": True,
                        "message": tag_result.get("message", "MCP tag added successfully")
                    }
            except Exception as e:
                tag_status = {
                    "tagged": False,
                    "message": f"Rule created successfully but MCP tag addition encountered an exception: {e}"
                }

            return {
                "success": True,
                "rule_id": result["rule_id"],
                "rule_name": rule_name,
                "is_update": is_update,
                "detected_status": auto_status,
                "creation_phase": creation_phase,
                "progress_percentage": progress_percentage,
                "completion_analysis": completion_analysis,
                "message": f"Rule {'updated' if is_update else 'created'} successfully with meaningful task aliases - Status: {auto_status} ({progress_percentage}% complete)",
                "rule_structure": rule_structure,
                "yaml_preview": yaml_preview,
                "timestamp": result.get("timestamp"),
                "status": result.get("status", auto_status),
                "design_notes_info": design_notes_result,
                "readme_info": readme_info,
                "tag_status": tag_status,
                "ui_url" : ui_url,
                "next_step": determine_next_action(creation_phase, completion_analysis)
            }
            
        except exception.CCowExceptionVO as e:
            return {"success": False, "error": f"Failed to create/update rule: {e.to_dict()}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to create/update rule: {e}"}
    
    @mcp.tool()
    def execute_rule(rule_name: str, from_date: str, to_date:str, rule_inputs: list[dict[str, Any]], applications: list[dict[str, Any]], is_application_data_provided_by_user: bool, ctx: Context | None = None) -> dict[str, Any]:
        """
        RULE EXECUTION WORKFLOW:

        **PARAMETER VALIDATION:
            Before starting any execution workflow, the tool should validate that required parameters
            (rule_name, rule_inputs) are present. Applications are optional and only needed for tasks
            that require credentials.**

        PREREQUISITE STEPS:
        0. **MANDATORY: Check rule status to ensure rule is fully developed before execution**
        1. User chooses to execute rule after creation
        2. Extract unique appTags from selected tasks (excluding 'nocredapp')
        3. APPLICATION CONFIGURATION (OPTIONAL - only for tasks requiring credentials):
            For tasks that need application credentials:
            - Fetch available applications via get_applications_for_tag().
            - Present them to the user for manual selection.
            - User decides to:
                a. Use an existing application, or
                b. Run with new credentials (not persisted or saved as an application).
            - Proceed after user confirmation.

            Note: Rules with only 'nocredapp' tasks can be executed without any application configuration.

        APPLICATION-TASK MATCHING LOGIC (when applications are needed):
        ================================
        - Applications are matched to tasks via 'appTags' labels
        - Tasks with 'nocredapp' appType do not require application configuration
        - **SHARED APPLICATION SUPPORT**: A single application CAN be used for multiple tasks
        if the user confirms they want to share the same credentials
        - When multiple tasks share the same appType AND require DIFFERENT applications,
        unique identifier key-value pairs MUST be added to distinguish them

        MATCHING SCENARIOS:
        1. **One application per task**: Each task has unique appType → straightforward matching
        2. **Shared application**: Multiple tasks share same appType AND same application
        - User confirms: "Use same application for all [appType] tasks? (yes/no)"
        - If yes: Single application covers all matching tasks
        - Application appTags should match the common appType
        3. **Multiple applications for same appType**: Different credentials needed for different tasks
        - Add unique identifier key (e.g., "purpose", "sourceSystem") to distinguish
        - Each application's appTags must include the unique identifier matching its target task

        APPLICATION CONFIGURATION FORMAT (when needed):
        For existing application (can be shared across multiple tasks):
        ```json
            [
                {
                    "applicationType": "[application_class_name from fetch_applications(appType)]",
                    "applicationId": "[Actual application ID chosen by user]",
                    "appTags": "[Complete object from rule spec.tasks[].appTags]"
                }
            ]
        ```

        For new credentials:
        ```json
            [
                {
                    "applicationType": "[application_class_name from fetch_applications(appType)]",
                    "appURL": "[Application URL from user (optional - can be empty string)]",
                    "credentialType": "[User chosen credential type]",
                    "credentialValues": {
                        "[User provided credentials]"
                    },
                    "appTags": "[Complete object from rule spec.tasks[].appTags]"
                }
            ]
        ```

        WORKFLOW FOR MULTIPLE TASKS WITH SAME APPTYPE:
        1. Detect tasks sharing same appType (excluding 'nocredapp')
        2. Ask user: "Tasks [task1, task2] both require [appType]. Options:
        a) Use SAME application/credentials for all tasks
        b) Use DIFFERENT applications (requires unique identifiers)"
        3. If SAME: User provides one application config with basic appTags
        4. If DIFFERENT:
        - Prompt for unique identifier key (e.g., "purpose", "sourceSystem")
        - User provides separate application configs with unique identifier values
        - Update task appTags with matching unique identifiers

        4. Build applications array (if needed) → get user confirmation
        5. Additional Inputs (optional):
            - Ask user: "Do you want to specify a date range for this execution?"
            - From Date (format: YYYY-MM-DD) - optional
            - To Date (format: YYYY-MM-DD) - optional
        6. Final confirmation → execute rule
        7. If execution starts successfully → call fetch_execution_progress()
        8. Rule Output File Display Process:
            a. Extract task outputs from execution results
            b. MANDATORY: Show output in this format:
                - TaskName: [task_name]
                - Files: [list of files]
            c. Ask: "View file contents? (yes/no)"
            d. If yes: Call fetch_output_file() for each requested file
            e. Display results with formatting
        9. Rule Publication (optional):
        - Ask user: "Do you want to publish this rule to make it available in ComplianceCow system? (yes/no)"
        - If yes: Call publish_rule() to publish the rule
        - If no: End workflow
        10. Modify rule such as add/delete tasks (optional):
        - Ask user: "Do you want to modify this rule? (yes/no)"
        - If yes: Call publish_rule() to publish the rule
        - If no: End workflow

        UI DISPLAY REQUIREMENT:
        - The file URL must ALWAYS be displayed to the user in the UI, allowing the user to view or download the file directly.

        CRITICAL: rule_inputs MUST be the complete spec.inputsMeta__ objects with ALL original fields
        (name, description, dataType, repeated, allowedValues, required, defaultValue, format, showField,
        explanation) plus the 'value' field. DO NOT send trimmed objects with only name/dataType/value.

        MANDATORY: The 'value' field content MUST also be copied to the 'defaultValue' field. Both fields
        must contain identical values. Example: if value="CSV", then defaultValue must also be "CSV".

        Args:
            rule_name: The name of the rule to be executed.
            from_date: (Optional) Start date provided by the user in the format YYYY-MM-DD.
            to_date: (Optional) End date provided by the user in the format YYYY-MM-DD.
            rule_inputs: Complete spec.inputsMeta__ objects with ALL fields plus 'value' field, and 'defaultValue' set to same value as 'value'.
            applications: Application configuration details. For rules with only 'nocredapp' tasks,
                         pass an empty list and the system will automatically use the hardcoded
                         nocredapp application structure.
            is_application_data_provided_by_user (bool):
                Indicates whether application data was provided by the user.
                - Set to True if user provided or configured application details during execution.
                - Set to False if using nocredapp (empty applications list) or pre-existing applications.

        Returns:
            Dict with execution results
        """
        try:
            # Define hardcoded nocredapp application structure
            NOCREDAPP_APPLICATION = {
                "applicationType": "NoCredApp",
                "appURL": "",
                "credentialType": "NoCred",
                "credentialValues": {
                    "Dummy": ""
                },
                "appTags": {
                    "appType": ["nocredapp"],
                    "environment": ["logical"],
                    "execlevel": ["app"]
                }
            }

            # If applications list is empty, add nocredapp application structure
            if not applications or len(applications) == 0:
                applications = [NOCREDAPP_APPLICATION]

            # Validate applications only if provided
            for application in applications:
                is_valid, result = False,{}
                application_id = application.get("applicationId", None)
                logger.debug("applictcation id: {}\n".format(application))

                if application_id:
                    if not is_valid_uuid(application_id):
                        return {"success": False, "error": f'The provided application ID: {application_id} is not valid. Please try again with a valid application ID.'}

                    headers = wsutils.create_header(ctx)
                    params = {
                        "id": application_id,
                        "validated": True
                    }

                    application_resp = wsutils.get(
                        path=wsutils.build_api_url(endpoint=constants.URL_FETCH_CREDENTIAL),
                        params=params,
                        header=headers
                    )
                    logger.debug("application_resp {}\n".format(application_resp))

                    if rule.is_valid_array(application_resp, "items"):
                        for item in application_resp["items"]:
                            app_type = item.get("appType", "")
                            if isinstance(app_type, str) and app_type.endswith("::"):
                                app_type = app_type[:-2]
                            cc_application={
                                "id": item.get("id"),
                                "name": item.get("credentialName"),
                                "appType": app_type,
                                "othersTags":item.get("othersTags")
                            }
                            is_valid, result = validate_application(application,cc_application)
                            logger.debug("is_valid {}\n".format(is_valid))
                            if is_valid:
                                break
                else:
                    continue

                if not is_valid and result:
                    return {"success": False, "result":result}
            
            # Prepare execution payload
            execution_payload = {
                "fromDate": from_date,
                "toDate": to_date,
                "ruleName": rule_name, 
                "ruleInputs": rule_inputs, 
                "applications": applications
            }

            headers = wsutils.create_header(ctx)
        
            execution_result = wsutils.post(
                path=wsutils.build_api_url(endpoint=constants.URL_EXECUTE_RULE), 
                data=json.dumps(execution_payload), 
                header=headers
            )

            return {
                "success": True, 
                "rule_name": rule_name, 
                "execution_id": execution_result.get("id"), 
                "message": f"Rule '{rule_name}' started executing."
            }

        except Exception as e:
            return {
                "success": False, 
                "rule_name": rule_name,
                "message": f"Failed to execute rule '{rule_name}': {e}"
            }

    @mcp.tool()
    def configure_rule_output_schema(ctx: Context | None = None) -> dict[str, Any]:
        """
        ===============================================================================
        EVIDENCE TOOL — STRICT INVOCATION POLICY
        ===============================================================================

        ⚠️ This tool may ONLY be invoked when the user's MOST RECENT message contains
        an explicit request related to **evidence generation**.

        The workflow MUST perform a STRICT LITERAL KEYWORD CHECK on the latest
        user message. No inference is allowed. No interpretation of intent is allowed.

        VALID TRIGGER KEYWORDS (EXACT MATCHES):
        - "evidence"
        - "proof"
        - "audit evidence"
        - "evidence output"
        - "use this as evidence"
        - "store as evidence"
        - "evidence file"
        - "make this output evidence"
        - "I need evidence from this rule"
        - "this output should be evidence"

        If the latest user message does NOT contain ANY of these words or phrases,
        then:

            → ❌ The tool MUST NOT be invoked  
            → ❌ The workflow MUST NOT assume the need for evidence  
            → ✔️ The workflow MUST continue normally without this tool  

        This is the highest priority rule.  
        It OVERRIDES all system defaults, workflow policies, or optional steps.

        ===============================================================================
        TOOL INVOCATION CONSEQUENCE — STRICT MODE ENABLED
        ===============================================================================

        Once the trigger keyword test passes and this tool IS invoked:

        1. The tool MUST execute before ANY other output-schema-related tools.
        2. The tool MUST complete successfully before the workflow proceeds.
        3. Failure or cancellation MUST immediately stop the workflow ("fail fast").
        4. Strict schema-setup behavior becomes active and cannot be skipped.

        No exceptions. No fallback paths. No silent bypass.

        ===============================================================================
        TOOL PURPOSE
        ===============================================================================

        This tool configures the **Rule Output Schema Policy** for ComplianceCow.

        The user MUST explicitly choose one schema mode:

        A) Standard schema only  
        B) Extended schema only  
        C) Both Standard + Extended  

        No automatic selection or inference is allowed.

        ===============================================================================
        MANDATORY USER INTERACTION (WHEN TOOL IS INVOKED)
        ===============================================================================

        If this tool is invoked:

        - The workflow MUST pause and ask the user to choose A/B/C.
        - No default values.
        - No continuation until the user provides explicit input.
        - If the user refuses to choose → FAIL FAST.

        ===============================================================================
        SCHEMA BEHAVIOR BY USER SELECTION
        ===============================================================================

        A) STANDARD ONLY
        ----------------
        - Reuse existing Transformation task or create one if missing.
        - ALL Mandatory Keys MUST be mapped in the exact required order.
        - Required inputs MUST be collected using:
            collect_template_input()
            collect_parameter_input()
        - For each required input:
            get_template_guidance('{task.name}', '<input_name>')
        - User MUST review and confirm before proceeding.

        B) EXTENDED ONLY
        ----------------
        - Preserve raw task output fields exactly as produced.
        - No ordering rules apply.
        - No mandatory schema enforcement.
        - Final output = last task execution output.

        C) BOTH (Standard + Extended)
        -----------------------------
        - Perform ALL Standard steps (A).
        - Add exactly ONE extended output:
            ExtendedData_<filename>
        - Map the last task output into ExtendedData_<filename>.
        - Prevent duplicate extended output nodes.
        - Require full validation + explicit user confirmation.

        ===============================================================================
        MANDATORY FIELDS (STRICT ORDER)
        ===============================================================================

        The Standard Schema MUST include the following keys in this EXACT order:

        1. System
        2. Source
        3. ResourceID
        4. ResourceName
        5. ResourceType
        6. ResourceLocation
        7. ResourceTags
        8. <Additional Keys based on user needs>
        9. ValidationStatusCode
        10. ValidationStatusNotes
        11. ComplianceStatus
        12. ComplianceStatusReason
        13. EvaluatedTime
        14. UserAction
        15. ActionStatus
        16. ActionResponseURL

        Case-sensitive. No renaming. No omission.

        ===============================================================================
        VALIDATION REQUIREMENTS
        ===============================================================================

        When the tool is invoked and before proceeding:

        - ALL mandatory keys MUST be mapped.
        - ALL collected inputs MUST be validated.
        - ALL guidance MUST be retrieved.
        - The user MUST confirm the schema configuration.
        - A Mermaid or D3 visualization MUST be generated immediately.
        - No downstream tool may execute before the chart is shown.

        ===============================================================================
        EXECUTION ORDER REQUIREMENT
        ===============================================================================

        If this tool completes successfully, the NEXT tool MUST be:

            prepare_input_collection_overview()

        No other tool may run in between.

        ===============================================================================
        SUMMARY OF THE GOLDEN RULE
        ===============================================================================

        **The ONLY condition that allows calling this tool is an explicit evidence
        keyword in the user's latest message. Without that, do NOT call the tool.**

        ===============================================================================
        """
        user_message = (
            "In ComplianceCow, evidence is stored in a structured format.\n"
            "Please select one of the following options:\n"
            "(a) Standard schema — Stores evidence in the ComplianceCow standard format (mandatory information only)\n"
            "(b) Extended schema — Stores the raw or modified response (all information, not in standard structure)\n"
            "(c) Standard + Extended — Stores evidence in both standard and extended formats"
        )

        return {
            "user_prompt": user_message,
            "message": "Proceeding to user selection: Standard schema, Extended schema, or Standard + Extended.",
            "next_step":"Generates a JS chart (Mermaid/D3) to visualize the rule's I/O fields and task structure. The chart must be shown in this chat immediately after user input. NOTE: No further processing should occur before this step."
        }

    @mcp.tool()
    def update_rule(rule_structure: dict[str, Any],existing_rule_name: str,ctx: Context | None = None) -> dict[str, Any]:
        """
            UPDATE RULE — REQUIRED BEHAVIOR
            --------------------------------------------------------------------
            You MUST update the rule object by modifying the dictionary provided
            in the variable `rule_structure`. All regenerated values (name,
            purpose, description) MUST be written directly back into
            rule_structure["meta"] before returning.

            RULE UPDATE LOGIC
            --------------------------------------------------------------------
            When modifying an existing rule (adding, removing, or updating
            tasks), always regenerate the complete rule object internally using
            the same logic defined in create_rule(), but call update_rule() —
            never create_rule().

            UPDATE STRATEGY
            --------------------------------------------------------------------
            1. You are allowed to modify ONLY these fields, and ONLY when they
            truly change based on user modifications:
            - rule_structure["meta"]["name"]
            - rule_structure["meta"]["purpose"]
            - rule_structure["meta"]["description"]

            2. All other fields in rule_structure MUST remain unchanged unless
            the user explicitly modified them.

            3. Never perform partial patches. Always rewrite the full final
            rule in rule_structure and return the entire updated object.

        RULE METADATA HANDLING:
            --------------------------------------------------------------------
            - meta.name: 
                * NEVER auto-rename the rule during updates
                * Only rename if user explicitly provides a new name
                * Preserve existing rule name in all update scenarios
            
            - meta.purpose:
                * Preserve existing purpose unless user explicitly provides new purpose
                * Do not auto-regenerate based on task changes
            
            - meta.description:
                * Preserve existing description unless user explicitly provides new description
                * Do not auto-regenerate based on task changes
            
            USER-INITIATED RENAME ONLY:
            - If user explicitly says "rename the rule to X" or "change the rule name to X"
            - Then and only then update meta.name with the user-provided name
            - Otherwise, always preserve the existing rule name

            OUTPUT REQUIREMENTS
            --------------------------------------------------------------------
            - Modify rule_structure IN PLACE.
            - Always return the entire updated rule_structure object.
            - Do not return anything else.
            - The updated rule_structure will be passed to update_rule() MCP tool.
        """
        logger.debug("------------- called update_rule -------------")
        logger.debug(f"rule_structure ::: {rule_structure}")
        logger.debug(f"existing_rule_name ::: {existing_rule_name}")
        rule_structure['existingRuleName'] = existing_rule_name
        return create_rule(rule_structure,True,ctx)

else:
    @mcp.tool()
    def create_rule(rule_structure: dict[str, Any], ctx: Context | None = None) -> dict[str, Any]:
        """Create a rule with the provided structure.

        COMPLETE RULE CREATION PROCESS WITH PROGRESSIVE SAVING:

        This tool now handles both initial rule creation and progressive updates during the rule creation workflow.
        It intelligently detects the completion status and sets appropriate metadata automatically.
        It returns the URL to view the rule in the UI once it is created display the URL in chat.

        ENHANCED FOR PROGRESSIVE SAVING:
        - Automatically detects rule completion status based on rule structure content
        - Determines if rule is in-progress, ready for execution, or needs more inputs
        - Handles both initial creation and updates of existing rules
        - No additional parameters needed - analyzes rule structure intelligently
        - Maintains all existing validation and creation logic
        - Preserves all original docstring instructions and requirements

        CRITICAL REQUIREMENT - INPUTS META:
        - `spec.inputsMeta__` is **mandatory** for all rules, and rule creation cannot proceed without it.

        AUTOMATIC STATUS DETECTION:
        - DRAFT: Rule has tasks but missing inputs or I/O mapping (5-85% complete)
        - READY_FOR_CREATION: All inputs collected but I/O mapping incomplete (85% complete)
        - ACTIVE: Complete rule with tasks, inputs, and I/O mapping (100% complete)

        RULE COMPLETION ANALYSIS:
        - Checks if tasks are defined in spec.tasks
        - Validates that `spec.inputsMeta__` exists
        - Counts collected inputs in spec.inputs vs spec.inputsMeta__
        - Validates I/O mapping presence and completeness in spec.ioMap
        - Analyzes outputsMeta__ for mandatory compliance outputs
        - Sets appropriate status and creation phase automatically

        PROGRESSIVE CREATION PHASES (Auto-detected):
        1. "initialized" - Basic rule info provided (5%)
        2. "tasks_selected" - Tasks chosen and defined (25%) 
        3. "collecting_inputs" - Individual inputs being collected (25-85%)
        4. "inputs_collected" - All inputs gathered, ready for I/O mapping (85%)
        5. "completed" - Final rule creation complete with I/O mapping (100%)

        ORIGINAL REQUIREMENTS MAINTAINED:
        - All existing validation rules still apply
        - Task alias validation in I/O mappings preserved
        - Primary app type determination logic maintained
        - Mandatory output requirements (CompliancePCT_, ComplianceStatus_, LogFile)
        - YAML preview and user confirmation workflow preserved
        - All existing error handling and validation checks

        CRITICAL: This tool should be called:
        1. After planning phase to create initial rule structure
        2. After each input collection to update rule progressively
        3. After input verification to finalize rule with I/O mapping
        4. Rule status and progress automatically detected each time

        PRE-CREATION REQUIREMENTS (Original):
        1. `spec.inputsMeta__` must be defined and contain valid input definitions
        2. All inputs must be collected through systematic workflow
        3. User must provide input overview confirmation  
        4. All template inputs processed via collect_template_input()
        5. All parameter values collected and verified
        6. User must confirm all input values before rule creation
        7. Primary application type must be determined
        8. Rule structure must be shown to user in YAML format for final approval

        STEP 1 - PRIMARY APPLICATION TYPE DETERMINATION (Preserved):
        Before creating rule structure, determine primary application type:
        1. Collect all unique appType tags from selected tasks
        2. Filter out 'nocredapp' (dummy placeholder value)
        3. Handle app type selection:
            - If only one valid appType: Use automatically
            - If multiple valid appTypes: Ask user to choose primary application
            - If no valid appTypes (all were nocredapp): Use 'generic' as default
        4. Set primary app type for appType, annotateType, and app fields (single value arrays)

        STEP 2 - RULE STRUCTURE WITH TASK ALIASES (Preserved):
        ```yaml
            apiVersion: rule.policycow.live/v1alpha1
            kind: rule
            meta:
                name: MeaningfulRuleName # Simple name. Without special characters and white spaces
                purpose: Clear statement based on user breakdown
                description: Detailed description combining all steps
                labels:
                    appType: [PRIMARY_APP_TYPE_FROM_STEP_1] # Single value array CRITICAL: Must be extracted from spec.tasks[].appTags.appType - NEVER use random values or user requirements
                    environment: [logical] # Array
                    execlevel: [app] # Array
                annotations:
                    annotateType: [PRIMARY_APP_TYPE_FROM_STEP_1] # Same as appType - MUST match a task's appType
            spec:
                inputs:
                InputName: [ACTUAL_USER_VALUE_OR_FILE_URL]  # Use original or unique names based on conflicts, omit duplicates
                inputsMeta__:
                - name: InputName             # unique name for the input
                description:                # purpose of the input
                dataType: FILE|HTTP_CONFIG|STRING|INT|FLOAT|BOOLEAN|DATE|DATETIME
                repeated:                   # true = multiple values allowed, false = single value
                allowedValues:              # if repeated=true: comma-separated input is split into array
                required:                   # value must be taken from task details.
                defaultValue: [ACTUAL_USER_VALUE] #values are collected from users, If the dataType is FILE or HTTP_CONFIG then the value should be filepath URL.
                format: [ACTUAL_FILE_FORMAT]      # only include for FILE types (json, yaml, toml, xml, etc.)
                showField: true                   # true = most important field, false = optional/less important
                outputsMeta__:
                - name: FinalOutput
                dataType: FILE|STRING|INT|FLOAT|BOOLEAN|DATE|DATETIME
                required: true
                defaultValue: [ACTUAL_RULE_OUTPUT_VALUE]
                tasks:
                - name: Step1TaskName # Original task names
                alias: step1 # Meaningful task aliases (simple descriptors)
                type: task
                appTags:
                    appType: [COPY_FROM_TASK_DEFINITION] # Keep original task appType
                    environment: [logical] # Array
                    execlevel: [app] # Array
                purpose: What this task does for Step 1
                - name: Step2TaskName
                alias: validation # Another meaningful alias
                type: task
                appTags:
                    appType: [COPY_FROM_TASK_DEFINITION]
                    environment: [logical] # Array
                    execlevel: [app] # Array
                purpose: What this task does for validation
                ioMap:
                - step1.Input.TaskInput:=*.Input.InputName  # Use task aliases in I/O mapping
                - validation.Input.TaskInput:=step1.Output.TaskOutput
                # MANDATORY: Always include these three outputs from the last task
                - '*.Output.FinalOutput:=validation.Output.TaskOutput'
                - '*.Output.CompliancePCT_:=validation.Output.CompliancePCT_'    # Compliance percentage from last task
                - '*.Output.ComplianceStatus_:=validation.Output.ComplianceStatus_'  # Compliance status from last task
                - '*.Output.LogFile:=validation.Output.LogFile'  # Log file from last task
        ```

        STEP 3 - I/O MAPPING WITH TASK ALIASES (Preserved):
        - Use golang-style assignment: destination:=source
        - 3-part structure: PLACE.DIRECTION.ATTRIBUTE_NAME
        - Always use EXACT attribute names from task specifications
        - Use meaningful task aliases instead of generic names
        - Ensure sequential data flow: Rule → Task1 → Task2 → Rule
        - Mandatory compliance outputs from last task

        STEP 4 - inputsMeta__ Cleanup:
        In spec.inputsMeta__, retain only the entries whose keys exist in spec.inputs. Remove any fields in spec.inputsMeta__ that are not present in spec.inputs.

        VALIDATION CHECKLIST (Preserved):
        □ Rule structure validation against schema
        □ Task alias validation in I/O mappings
        □ Primary app type determination
        □ Input/output specifications validation
        □ Mandatory compliance outputs present
        □ Sequential data flow in I/O mappings

        Args:
            rule_structure: Complete rule structure with any level of completion

        Returns:
            Result of rule creation including auto-detected status and completion level
        """

        try:
            if rule.is_valid_key(rule_structure,"spec") and  rule.is_valid_array(rule_structure["spec"],"tasks"):
                tasks = rule_structure["spec"]["tasks"]
                for task in tasks:
                    if rule.is_valid_key(task,"aliasref") and not rule.is_valid_key(task,"alias"):
                        task["alias"] = task["aliasref"]
                rule_structure["spec"]["tasks"] = tasks
            # Validate rule structure (preserve original validation)
            validation_result = rule.validate_rule_structure(rule_structure)
            if not validation_result["valid"]:
                return {"success": False, "error": "Invalid rule structure", "validation_errors": validation_result["errors"]}

            # Additional validation for task aliases in I/O mappings (preserved from original)
            tasks_section = rule_structure.get("spec", {}).get("tasks", [])
            io_map = rule_structure.get("spec", {}).get("ioMap", [])
            
            # Extract task aliases from tasks section for validation
            valid_aliases = set()
            for task in tasks_section:
                if "alias" in task:
                    valid_aliases.add(task["alias"])
            
            # Validate I/O mappings use correct task aliases (preserved validation)
            io_mapping_errors = []
            for mapping in io_map:
                if "." in mapping and ":=" in mapping:
                    left_side = mapping.split(":=")[0].strip()
                    right_side = mapping.split(":=")[1].strip()
                    
                    # Check left side for task alias
                    if not left_side.startswith("*."):
                        alias_part = left_side.split(".")[0]
                        if alias_part not in valid_aliases and alias_part != "*":
                            return {
                                "success": False,
                                "error": f"Unknown task alias '{alias_part}' in I/O mapping: {mapping}. Valid aliases: {list(valid_aliases)}"
                            }
                    
                    # Check right side for task alias  
                    if not right_side.startswith("*."):
                        alias_part = right_side.split(".")[0]
                        if alias_part not in valid_aliases and alias_part != "*":
                            return {
                                "success": False,
                                "error": f"Unknown task alias '{alias_part}' in I/O mapping: {mapping}. Valid aliases: {list(valid_aliases)}"
                            }

                    # Validate right side (source) output exists in task
                    if not right_side.startswith("*."):
                        parts = right_side.split(".")
                        if len(parts) >= 3:  # task_alias.Output.output_name format
                            source_task_alias = parts[0]
                            direction = parts[1]
                            output_name = parts[2]
                            
                            if direction == "Output":
                                # Find the task with this alias
                                source_task = None
                                for task in tasks_section:
                                    if task.get("alias") == source_task_alias:
                                        source_task = task
                                        break
                                
                                if source_task:
                                    # Get task details to validate output exists
                                    task_name = source_task.get("name")
                                    task_details= get_task_details(task_name, ctx)
                                    if task_details.get("error"):
                                        io_mapping_errors.append(f"Could not validate task '{task_name}': {task_details['error']}")
                                    else:
                                        # Check if the output exists in task definition
                                        task_outputs = task_details.get("outputs", [])
                                        valid_output_names = [out["name"] for out in task_outputs]
                                        
                                        if output_name not in valid_output_names:
                                            io_mapping_errors.append(
                                                f"Output '{output_name}' not found in task '{task_name}'. "
                                                f"Valid outputs: {valid_output_names}"
                                            )  

            # Return validation errors if any I/O mapping issues found
            if io_mapping_errors:
                return {
                    "success": False,
                    "error": "I/O mapping validation failed",
                    "validation_errors": io_mapping_errors,
                    "message": "Some I/O mappings reference outputs that don't exist in the specified tasks"
                }    

            # NEW: AUTOMATIC STATUS DETECTION based on rule content
            spec = rule_structure.get("spec", {})
            meta = rule_structure.get("meta", {})

            # MANDATORY: Fetch application class name for the primary app type
            primary_app_type_array = meta.get("labels", {}).get("appType", [])
            primary_app_type = primary_app_type_array[0] if primary_app_type_array else None
            applications_response = fetch_applications(ctx)
            application_class_name = None

            # Find matching application class name for primary app type
            if applications_response and applications_response.get("success") and primary_app_type:
                for app in applications_response.get("applications"):
                    app_type = app.get("app_type")
                    # Check if any app type from primary_app_type matches any app type from the application
                    if app_type == primary_app_type:
                        application_class_name = app.get("application_class_name")
                        break
                # Add app    
                rule_structure["meta"]["app"] = application_class_name     
            
            
            
            # Analyze rule completeness for auto-detection
            tasks = spec.get("tasks", [])
            inputs = spec.get("inputs", {})
            inputs_meta = spec.get("inputsMeta__", [])
            io_map = spec.get("ioMap", [])
            outputs_meta = spec.get("outputsMeta__", [])
            
            # Check for mandatory compliance outputs
            mandatory_outputs = ["CompliancePCT_", "ComplianceStatus_", "LogFile"]
            has_mandatory_outputs = all(
                any(output.get("name") == req_output for output in outputs_meta) 
                for req_output in mandatory_outputs
            )
            
            # Completion analysis
            completion_analysis = {
                "has_tasks": len(tasks) > 0,
                "has_inputs": len(inputs) > 0 and any(
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                    for value in inputs.values()
                ),
                "has_inputs_meta": len(inputs_meta) > 0,
                "has_io_mapping": len(io_map) > 0,
                "has_mandatory_outputs": has_mandatory_outputs,
                "tasks_count": len(tasks),
                "inputs_collected": sum(1 for value in inputs.values() if (
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                )),
                "inputs_meta_count": len(inputs_meta),
                "io_mappings_count": len(io_map),
                "inputs_match_metadata": len(inputs) == len(inputs_meta),
                "total_inputs_needed": len(inputs_meta),  # Total inputs from inputsMeta__
                "inputs_completion_percentage": (sum(1 for value in inputs.values() if (
                    (isinstance(value, str) and value.strip() != "" and value != "<<MINIO_FILE_PATH>>" and not value.startswith("<<")) or
                    (isinstance(value, bool)) or
                    (isinstance(value, (int, float)) and value is not None)
                )) / max(len(inputs_meta), 1)) * 100 if inputs_meta else 0
            }
            
            # Enhanced automatic status determination
            if (completion_analysis["has_io_mapping"] and 
                completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"] and  # All inputsMeta__ inputs collected
                completion_analysis["has_tasks"] and
                completion_analysis["has_mandatory_outputs"] and
                completion_analysis["inputs_match_metadata"]):
                auto_status = "ACTIVE"
                creation_phase = "completed"
                progress_percentage = 100
                
            elif (completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"] and  # All inputsMeta__ inputs collected
                completion_analysis["has_tasks"] and
                completion_analysis["has_mandatory_outputs"] and
                completion_analysis["inputs_match_metadata"]):
                auto_status = "READY_FOR_CREATION"  
                creation_phase = "inputs_collected"
                progress_percentage = 85
                
            elif completion_analysis["has_tasks"]:
                if completion_analysis["inputs_collected"] > 0:  # Some inputs have values
                    auto_status = "DRAFT"
                    creation_phase = "collecting_inputs"
                    # Calculate progress: 25% base + (input completion percentage * 0.6)
                    progress_percentage = min(25 + int(completion_analysis["inputs_completion_percentage"] * 0.6), 85)
                else:
                    auto_status = "DRAFT"
                    creation_phase = "tasks_selected"
                    progress_percentage = 25
            else:
                auto_status = "DRAFT"
                creation_phase = "initialized"
                progress_percentage = 5

            # Set detected status in meta (don't override if explicitly provided and valid)
            if "status" not in meta or meta["status"] not in ["DRAFT", "READY_FOR_CREATION", "ACTIVE"]:
                rule_structure["meta"]["status"] = auto_status
            if "creation_phase" not in meta:
                rule_structure["meta"]["creation_phase"] = creation_phase

            # Add automatic timestamps (preserve existing if present)
            current_time = datetime.now().isoformat()
            if "created_at" not in meta:
                rule_structure["meta"]["created_at"] = current_time
            rule_structure["meta"]["last_updated"] = current_time

            # Add/update progress tracking with detailed analysis
            rule_structure["meta"]["progress"] = {
                "percentage": progress_percentage,
                "phase": creation_phase,
                "completion_analysis": completion_analysis,
                "next_steps": determine_next_steps(creation_phase, completion_analysis),
                "estimated_completion": estimate_completion_time(completion_analysis)
            }

            # Check if rule already exists (for updates vs creation)
            existing_rule = fetch_rule(rule_structure["meta"]["name"], ctx)
            is_update = existing_rule["success"]

            # Generate YAML preview for user confirmation (preserved from original)
            yaml_preview = rule.generate_yaml_preview(rule_structure)

            # Call your existing create_rule_api (preserved)
            result = rule.create_rule_api(rule_structure, ctx)

            # Auto-generate design notes info (preserved from original)
            design_notes_result = {
                "auto_generated": True, 
                "message": "Design notes will be auto-generated using comprehensive internal template",
                "next_action": "Call create_design_notes(rule_name, design_notes_structure) to generate and save design notes"
            }

            readme_info = {
                "auto_generated": True, 
                "message": "README will be auto-generated using a comprehensive internal template",
                "next_action": "Call create_rule_readme(rule_name, readme_content) to generate and save the README"
            }
            
            rule_name = rule_structure["meta"]["name"]

            # Build UI URL
            base_host = constants.host.rstrip("/api") if hasattr(constants, "host") and isinstance(constants.host, str) else getattr(constants, "host", "")
            ui_url = f"{base_host}/ui/create-pc-rule?name={rule_name}&catalog=localcatalog" if base_host else ""
                
            #Add MCP tag to the rule with proper error handling
            try:
                tag_result = add_rule_tag(rule_name, ctx)
                if not tag_result.get("success", False):
                    tag_message = tag_result.get("message", "Unknown error occurred")
                    tag_status = {
                        "tagged": False,
                        "message": f"Rule created successfully but MCP tag addition failed: {tag_message}"
                    }
                else:
                    tag_status = {
                        "tagged": True,
                        "message": tag_result.get("message", "MCP tag added successfully")
                    }
            except Exception as e:
                tag_status = {
                    "tagged": False,
                    "message": f"Rule created successfully but MCP tag addition encountered an exception: {e}"
                }

            return {
                "success": True,
                "rule_id": result["rule_id"],
                "rule_name": rule_name,
                "is_update": is_update,
                "detected_status": auto_status,
                "creation_phase": creation_phase,
                "progress_percentage": progress_percentage,
                "completion_analysis": completion_analysis,
                "message": f"Rule {'updated' if is_update else 'created'} successfully with meaningful task aliases - Status: {auto_status} ({progress_percentage}% complete)",
                "rule_structure": rule_structure,
                "yaml_preview": yaml_preview,
                "timestamp": result.get("timestamp"),
                "status": result.get("status", auto_status),
                "design_notes_info": design_notes_result,
                "readme_info": readme_info,
                "tag_status": tag_status,
                "ui_url" : ui_url,
                "next_step": determine_next_action(creation_phase, completion_analysis)
            }
            
        except exception.CCowExceptionVO as e:
            return {"success": False, "error": f"Failed to create rule: {e.to_dict()}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to create rule: {e}"}
        
    @mcp.tool()
    def execute_rule(rule_name: str, from_date: str, to_date:str, rule_inputs: list[dict[str, Any]], applications: list[dict[str, Any]], is_application_data_provided_by_user: bool, ctx: Context | None = None) -> dict[str, Any]:
        """
        RULE EXECUTION WORKFLOW:

        PREREQUISITE STEPS:
        0. **MANDATORY: Check rule status to ensure rule is fully developed before execution**
        1. User chooses to execute rule after creation
        2. Extract unique appTags from selected tasks (excluding 'nocredapp')
        3. APPLICATION CONFIGURATION (OPTIONAL - only for tasks requiring credentials):
            For tasks that need application credentials:
            - Fetch available applications via get_applications_for_tag().
            - Present them to the user for manual selection.
            - User decides to:
                a. Use an existing application, or
                b. Run with new credentials (not persisted or saved as an application).
            - Proceed after user confirmation.

            Note: Rules with only 'nocredapp' tasks can be executed without any application configuration.

        APPLICATION-TASK MATCHING LOGIC (when applications are needed):
        ================================
        - Applications are matched to tasks via 'appTags' labels
        - Tasks with 'nocredapp' appType do not require application configuration
        - **SHARED APPLICATION SUPPORT**: A single application CAN be used for multiple tasks
          if the user confirms they want to share the same credentials
        - When multiple tasks share the same appType AND require DIFFERENT applications,
          unique identifier key-value pairs MUST be added to distinguish them

        MATCHING SCENARIOS:
        1. **One application per task**: Each task has unique appType → straightforward matching
        2. **Shared application**: Multiple tasks share same appType AND same application
           - User confirms: "Use same application for all [appType] tasks? (yes/no)"
           - If yes: Single application covers all matching tasks
           - Application appTags should match the common appType
        3. **Multiple applications for same appType**: Different credentials needed for different tasks
           - Add unique identifier key (e.g., "purpose", "sourceSystem") to distinguish
           - Each application's appTags must include the unique identifier matching its target task

        APPLICATION CONFIGURATION FORMAT (when needed):
        For existing application (can be shared across multiple tasks):
            ```json
            [
                {
                    "applicationType": "[application_class_name from fetch_applications(appType)]",
                    "applicationId": "[Actual application ID chosen by user]",
                    "appTags": "[Complete object from rule spec.tasks[].appTags]"
                }
            ]
            ```

        For new credentials:
            ```json
            [
                {
                    "applicationType": "[application_class_name from fetch_applications(appType)]",
                    "appURL": "[Application URL from user (optional - can be empty string)]",
                    "credentialType": "[User chosen credential type]",
                    "credentialValues": {
                        "[User provided credentials]"
                    },
                    "appTags": "[Complete object from rule spec.tasks[].appTags]"
                }
            ]
            ```

        WORKFLOW FOR MULTIPLE TASKS WITH SAME APPTYPE:
        1. Detect tasks sharing same appType (excluding 'nocredapp')
        2. Ask user: "Tasks [task1, task2] both require [appType]. Options:
           a) Use SAME application/credentials for all tasks
           b) Use DIFFERENT applications (requires unique identifiers)"
        3. If SAME: User provides one application config with basic appTags
        4. If DIFFERENT:
           - Prompt for unique identifier key (e.g., "purpose", "sourceSystem")
           - User provides separate application configs with unique identifier values
           - Update task appTags with matching unique identifiers

        4. Build applications array (if needed) → get user confirmation
        5. Additional Inputs (optional):
            - Ask user: "Do you want to specify a date range for this execution?"
            - From Date (format: YYYY-MM-DD) - optional
            - To Date (format: YYYY-MM-DD) - optional
        6. Final confirmation → execute rule
        7. If execution starts successfully → call fetch_execution_progress()
        8. Rule Output File Display Process:
            a. Extract task outputs from execution results
            b. MANDATORY: Show output in this format:
                - TaskName: [task_name]
                - Files: [list of files]
            c. Ask: "View file contents? (yes/no)"
            d. If yes: Call fetch_output_file() for each requested file
            e. Display results with formatting
        9. Rule Publication (optional):
        - Ask user: "Do you want to publish this rule to make it available in ComplianceCow system? (yes/no)"
        - If yes: Call publish_rule() to publish the rule
        - If no: End workflow

        UI DISPLAY REQUIREMENT:
        - The file URL must ALWAYS be displayed to the user in the UI, allowing the user to view or download the file directly.

        CRITICAL: rule_inputs MUST be the complete spec.inputsMeta__ objects with ALL original fields
        (name, description, dataType, repeated, allowedValues, required, defaultValue, format, showField,
        explanation) plus the 'value' field. DO NOT send trimmed objects with only name/dataType/value.

        MANDATORY: The 'value' field content MUST also be copied to the 'defaultValue' field. Both fields
        must contain identical values. Example: if value="CSV", then defaultValue must also be "CSV".

        Args:
            rule_name: The name of the rule to be executed.
            from_date: (Optional) Start date provided by the user in the format YYYY-MM-DD.
            to_date: (Optional) End date provided by the user in the format YYYY-MM-DD.
            rule_inputs: Complete spec.inputsMeta__ objects with ALL fields plus 'value' field, and 'defaultValue' set to same value as 'value'.
            applications: Application configuration details. For rules with only 'nocredapp' tasks,
                         pass an empty list and the system will automatically use the hardcoded
                         nocredapp application structure.
            is_application_data_provided_by_user (bool):
                Indicates whether application data was provided by the user.
                - Set to True if user provided or configured application details during execution.
                - Set to False if using nocredapp (empty applications list) or pre-existing applications.

        Returns:
            Dict with execution results
        """
        try:
            # Define hardcoded nocredapp application structure
            NOCREDAPP_APPLICATION = {
                "applicationType": "NoCredApp",
                "appURL": "",
                "credentialType": "NoCred",
                "credentialValues": {
                    "Dummy": ""
                },
                "appTags": {
                    "appType": ["nocredapp"],
                    "environment": ["logical"],
                    "execlevel": ["app"]
                }
            }

            # If applications list is empty, add nocredapp application structure
            if not applications or len(applications) == 0:
                applications = [NOCREDAPP_APPLICATION]

            # Validate applications only if provided
            for application in applications:
                is_valid, result = False,{}
                application_id = application.get("applicationId", None)
                logger.debug("applictcation id: {}\n".format(application))

                if application_id:
                    if not is_valid_uuid(application_id):
                        return {"success": False, "error": f'The provided application ID: {application_id} is not valid. Please try again with a valid application ID.'}

                    headers = wsutils.create_header(ctx)
                    params = {
                        "id": application_id,
                        "validated": True
                    }

                    application_resp = wsutils.get(
                        path=wsutils.build_api_url(endpoint=constants.URL_FETCH_CREDENTIAL),
                        params=params,
                        header=headers
                    )
                    logger.debug("application_resp {}\n".format(application_resp))

                    if rule.is_valid_array(application_resp, "items"):
                        for item in application_resp["items"]:
                            app_type = item.get("appType", "")
                            if isinstance(app_type, str) and app_type.endswith("::"):
                                app_type = app_type[:-2]
                            cc_application={
                                "id": item.get("id"),
                                "name": item.get("credentialName"),
                                "appType": app_type,
                                "othersTags":item.get("othersTags")
                            }
                            is_valid, result = validate_application(application,cc_application)
                            logger.debug("is_valid {}\n".format(is_valid))
                            if is_valid:
                                break
                else:
                    continue

                if not is_valid and result:
                    return {"success": False, "result":result}
            
            # Prepare execution payload
            execution_payload = {
                "fromDate": from_date,
                "toDate": to_date,
                "ruleName": rule_name, 
                "ruleInputs": rule_inputs, 
                "applications": applications
            }

            headers = wsutils.create_header(ctx)
        
            execution_result = wsutils.post(
                path=wsutils.build_api_url(endpoint=constants.URL_EXECUTE_RULE), 
                data=json.dumps(execution_payload), 
                header=headers
            )

            return {
                "success": True, 
                "rule_name": rule_name, 
                "execution_id": execution_result.get("id"), 
                "message": f"Rule '{rule_name}' started executing."
            }

        except Exception as e:
            return {
                "success": False, 
                "rule_name": rule_name,
                "message": f"Failed to execute rule '{rule_name}': {e}"
            }
            
    @mcp.tool()
    def configure_rule_output_schema(ctx: Context | None = None) -> dict[str, Any]:
        """
        PREREQUISITE — MUST RUN FIRST (NON-SKIPPABLE)
        This tool is a hard prerequisite and MUST be executed successfully before the `prepare_input_collection_overview()` tool (and any downstream rule-creation or evaluation steps). 
        If this tool has not run or did not complete, the workflow MUST fail fast with an explicit error.
        
        PURPOSE
        Establish the rule's output schema policy for ComplianceCow and apply any required transformations. In ComplianceCow, we maintain a standard format for storing evidence records. The user MUST choose one of the following rule output options:

        1) Standard schema only (ComplianceCow structured response fields)
        2) Extended schema only (all fields from the source response)
        3) Both standard + extended

        USER PROMPT (MANDATORY — NEVER SKIPPABLE)
        The workflow MUST always pause and explicitly prompt the user before proceeding.  
        This step CANNOT be bypassed, defaulted, auto-selected, or inferred.  
        If the user has not actively selected one of (a), (b), or (c), this tool MUST fail fast with a clear error message and stop execution.  

        VALIDATION & ENFORCEMENT
        - This tool is NON-SKIPPABLE. If not executed, or if the user does not provide an explicit choice (a/b/c), the workflow MUST stop immediately with an error.  
        - No implicit defaults, assumptions, or auto-selections are allowed.  
        - Mandatory Key mapping rules still apply if Standard schema is chosen.

        BEHAVIOR BY SELECTION

        A) If user selects STANDARD ONLY:
        - If the pipeline already ends with a Transformation task, reuse the existing Transformation task instead of appending a new one.
        - Otherwise, append a Transformation task at the END of the selected task pipeline.
        - In the Transformation task, map ALL Mandatory Keys (listed below).
        - Values for these keys MUST be taken from the pipeline's input file(s) and/or upstream task outputs, following the Deeper Analysis Rules.
        - Continue collecting inputs for the Transformation task using:
            `collect_template_input()` or `collect_parameter_input()`.
        - For each input that requires user guidance, call:
            `get_template_guidance('{task.name}', '<input_name>')`
        to display the expected input format to the user.
        - Ask the user to review and confirm OR edit the configuration before proceeding.
        - Do not proceed unless all Mandatory Keys are mapped and the configuration is confirmed (fail fast with guidance).

        B) If user selects EXTENDED ONLY:
        - The Extended schema is a NON-STANDARD structure. It preserves the raw fields from the source response without enforcing ComplianceCow's standard schema format or mandatory key order.
        - Use the LAST task's output directly as the Extended schema output.
        - No mandatory field ordering or schema enforcement is applied — the structure is kept as-is for completeness and traceability.

        C) If user selects BOTH:
        - Perform all steps from (A) to create the Standard schema:
        * Append a Transformation task at the END of the selected task pipeline.
        * Map ALL Mandatory Keys in the exact required order.
        * Include <AdditionalKeysBasedOnUseCase> as needed for compliance.
        - Also add the Extended schema as a NON-STANDARD structure:
        * Create exactly ONE output field named: ExtendedData_<filename>.
            <filename> MUST be determinable from the use case (e.g., source, resource, or input artifact name).
        * Map the SAME LAST task output that is used as the input to the Transformation task into ExtendedData_<filename>.
        * Do NOT create duplicate extended outputs (for example, do not add both
            ExtendedData_JSONToCSV and ConvertedCSVFile if they contain the same data).
            Only ExtendedData_<filename> must exist.
        - Continue collecting inputs for the Transformation task using:
            collect_template_input() or collect_parameter_input().
        - For each input that requires user guidance, call:
            get_template_guidance('{task.name}', '<input_name>')
        to display the expected input format to the user.
        - Ask the user to review and confirm OR edit the configuration before proceeding.
        - Do not proceed unless:
        * All Mandatory Keys are mapped and validated in order
        * Configuration is confirmed by the user

        DEEPER ANALYSIS RULES
        - Always extract and map the core Mandatory Keys required for compliance.
        - For <AdditionalKeysBasedOnUseCase>, determine the minimal required fields based on the user's specific use case and map them under the Standard schema.
        - If additional fields are critical for the use case, map them explicitly into the Standard schema.
        - If fields are non-critical but useful, preserve them under `ExtendedData_<filename>`.
        - If MCP cannot store certain fields, the tool MUST explain the omission clearly to the user before proceeding and request confirmation if needed.

        MANDATORY KEYS (MUST ALWAYS BE MAPPED — IN THIS EXACT ORDER)
        - System
        - Source
        - ResourceID
        - ResourceName
        - ResourceType
        - ResourceLocation
        - ResourceTags
        - <Important Keys Based On User's Use Case>
            (for example: fields from the response file such as user_id, username, email,
            license_type, assigned_date, last_login_date, last_activity_date)
        - ValidationStatusCode
        - ValidationStatusNotes
        - ComplianceStatus
        - ComplianceStatusReason
        - EvaluatedTime
        - UserAction
        - ActionStatus
        - ActionResponseURL

        VALIDATION & ENFORCEMENT
        - This tool is NON-SKIPPABLE. If not executed, or if any Mandatory Key mapping is missing for the chosen Standard schema path, the workflow MUST stop with an error.
        - Key names are case-sensitive and MUST NOT be renamed.
        - The tool MUST persist the chosen option and mappings so that downstream tools consume a consistent schema contract.
        - The workflow MUST NOT proceed to `prepare_input_collection_overview()` until:
            * Inputs are collected via `collect_template_input()` or `collect_parameter_input()`
            * `get_template_guidance()` has been used for each input needing guidance
            * The user has confirmed or edited the configuration
            * All Mandatory Keys are mapped and validated in order
        - Mandatory, a JS chart (Mermaid/D3) MUST be generated to visualize the rule's I/O field structure. The chart must be displayed in this chat immediately after user input, and no further processing is allowed until this step is completed.

        EXECUTION ORDER GUARANTEE
        On success, and ONLY after input collection and configuration confirmation,
        the next tool to run MUST be `prepare_input_collection_overview()`.
        """
        user_message = (
            "In ComplianceCow, evidence is stored in a structured format.\n"
            "Please select one of the following options:\n"
            "(a) Standard schema — Stores evidence in the ComplianceCow standard format (mandatory information only)\n"
            "(b) Extended schema — Stores the raw or modified response (all information, not in standard structure)\n"
            "(c) Standard + Extended — Stores evidence in both standard and extended formats"
        )

        return {
            "user_prompt": user_message,
            "message": "Proceeding to user selection: Standard schema, Extended schema, or Standard + Extended.",
            "next_step":"Generates a JS chart (Mermaid/D3) to visualize the rule's I/O fields and task structure. The chart must be shown in this chat immediately after user input. NOTE: No further processing should occur before this step."
        }

if constants.ENABLE_CVE_TOOLS:
    @mcp.tool()
    def fetch_cves(ctx: Context | None = None) -> list[CVEEntryVO]|str:
        """
        Return the CVE catalog with remediation details.

        CVE RULE CREATION INSTRUCTIONS:
            - First get the CVEs from this tool.
            - If the user requests a CVE that is not available from this tool, use `execute_shell_command`
            to fetch the CVE data and remediation details.

        When creating a rule for a specific CVE:
            1. Briefly summarize the CVE, including the affected component, impact, and severity.
            2. Present all valid remediations.
            3. After listing the remediations, show the plan for each remediation: which APIs will be used, which fields will be checked, and how that remediation will be verified in the target system.
            4. Create the rule to determine both whether the target resource is affected and whether any valid remediation is already in place.
            5. Check version, deployment pattern, settings or configuration, and any other relevant signal that can confirm exposure or remediation coverage.
            6. Only if remediation differs by deployment pattern or any other condition, first identify that condition and then verify only the applicable remediation path. Example: for ingress-nginx, Helm-managed and manually deployed setups can require different remediation checks.
            7. If the resource is affected, clearly state why it is affected and what remediation is required. If the resource is not affected because a valid remediation is already applied, clearly state which remediation is in place.
            8. Include all checks performed so the remediation decision is traceable.
            9. Use standard schema and include evidence columns `ClusterName`, `NameSpace`, and `CVE`, plus extra columns `ChecksPerformed`, `MatchedRemediation`, `AffectedReason`, `Remediation`, and `PatchContent`.
            10. If a remediation can be applied as a patch, include the exact patch content in `PatchContent` so it can be used with `kubectl patch <resource-type> <resource-name> -p '<patch-json-or-yaml>'`.
                    
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cve_path = os.path.join(script_dir, "cve_catalog.json")

        if not os.path.exists(cve_path):
            return f"Missing CVE catalog file"

        with open(cve_path, "r", encoding="utf-8") as file:
            try:
                raw_items = json.load(file)
                return [CVEEntryVO.model_validate(item) for item in raw_items]
            except json.JSONDecodeError as e:
                return "Invalid JSON in CVE catalog: {e}"