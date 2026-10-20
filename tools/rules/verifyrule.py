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
    if constants.ENABLE_CONTEXTUAL_VECTOR_SEARCH:
        @mcp.tool()
        def fetch_tasks_suggestions(user_requirement: str, summary_string: str, ctx: Context | None = None) -> dict[str, Any]:
            
            """
            Resource for intelligent task suggestion based on user requirements.

            PURPOSE:
            - Analyze the user's requirement and generate a concise **summary string** that
            captures the intent in natural language (not bullet points, not verbatim input).
            - Use the summary string to query task suggestions via the Suggestions API.
            - Match suggested tasks with the user’s intent to prevent redundant or duplicate task creation.
            - Provide resumption options if partially developed tasks exist.

            SUMMARY STRING CREATION:
            - Always derive a clear, single-paragraph summary string from the user's input.
            - Convert it into a structured summary string that clearly outlines each step/task that must be performed.
            - Each part of the summary string should represent an atomic action that could later be mapped to an individual task.
            - The summary must express the intended goal in natural language.
            - This summary string is what will be passed to `fetch_rules_and_tasks_suggestions`.
            - Example:
                Input: "Create a rule to update CC workflow user actions that remain 'in progress' for more than one day.
                The process should first check if any workflow user actions are pending, meaning their status is still 'in progress'.
                If such actions exist and were assigned more than one day ago, they should be marked as completed. Finally,
                send a notification to the user informing them that their action has been automatically marked as completed after waiting for a long time."
                Summary: "Check for workflow user actions with status 'in progress'.
                If they were assigned more than one day ago, mark them as completed and notify the user about the auto-completion."

            DECISION LOGIC:
            - If **matching tasks** are found in the suggestions:
                * Present them to the user for selection.
                * Include explanation of purpose, description, and relevance.
            - If **no matching tasks** are found:
                * FALLBACK: Call `get_tasks_summary()` to provide a broader list of tasks for discovery.
                * Clearly inform the user that no direct match was found and present fallback results.

            AUTOMATIC WORKFLOW HANDLING:
            - Detect if suggested tasks are only intermediate steps (splitting, extraction, validation, processing).
            - If intermediate: automatically recommend additional tasks that can complete the workflow.
            - Never leave the user with incomplete workflows.
            - Ensure the final task suggestions always lead to actionable, consumable deliverables.

            MANDATORY FUNCTIONALITY:
            - Generate summary string from raw requirement.
            - Fetch task suggestions using this summary.
            - Validate suggestions and ensure workflow completeness.
            - If suggestions fail → fallback to `get_tasks_summary()`.
            - Always explain reasoning when no suggestions are found and why fallback is triggered.
            
            NEXT STEPS AFTER MATCH:
            - Once matching task suggestions are presented to the user:
                * Wait for user selection.
                * Once matching tasks are found, show to user with explanation before fetching full details using `tasks://details/{task_name}`.
                * For each selected task, fetch complete task details using `tasks://details/{task_name}`.
                * Provide the full description, input/output parameters, templates, and usage guidance.
            - Apply the same **workflow completeness enforcement** as in `get_tasks_summary`:
                * If the selected task is only an intermediate step, automatically recommend additional tasks to complete the workflow.
                * Ensure that the final set of tasks always produces actionable, consumable deliverables.

            DEDUPLICATION HANDLING:
            - The `fetch_rules_and_tasks_suggestions` API may return the same task name multiple times
            with different descriptions and purpose.
            - In such cases:
                * Consolidate results under a single task entry.
                * Merge or summarize all unique descriptions and purpose into one combined explanation.
                * Ensure the final presentation avoids duplicates while still capturing all variations.
            - Always prioritize clarity: the user should see only one task name, with a rich combined description
            that reflects all possible contexts.

            """
            try:
                task_response = rule.fetch_rules_and_tasks_suggestions(query=summary_string, identifierType="tasks", ctx=ctx)
                if not task_response:
                    return {"error": f"No task found that matches the specified requirements."}
                return task_response
            except Exception as e:
                return {
                    "error": f"An error occurred while retrieving the task with the specified details: {e}"
                }
        
        


    @mcp.tool()
    def get_applications_for_tag( tag_name: str, additional_tags: dict[str, list[str]] | None = None, ctx: Context | None = None ) -> dict[str, Any]: 
        """
        Get available applications for a specific app tag.

        APPLICATION RETRIEVAL:
        - Fetches all existing applications configured for the specified app tag.
        - Returns a list of applications with ID, name, and app type.
        - Used during rule execution to present application choices to the user.
        - Optionally filters by additional tags (e.g., purpose, sourceSystem) for precise matching.

        Args:
            tag_name (str): The app tag name to get applications for. 
                            This parameter is mandatory and must not be empty.
            additional_tags (dict[str, list[str]]): Optional additional tags to filter applications.
                            Example: {"purpose": ["source-repo"]} to find apps with specific purpose.

        Returns:
            dict: A dictionary containing available applications for the specified tag.

        Raises:
            ValueError: If tag_name is not provided or is empty.
        """
        try:
            header = wsutils.create_header(ctx)

            params = {
                "app_type_tag": tag_name,
                "fields": "basic",
                "validated": True
            }

            applications = []

            applications_resp = wsutils.get(
                path=wsutils.build_api_url(endpoint=constants.URL_FETCH_CREDENTIAL), 
                params=params, 
                header=header
            )

            if rule.is_valid_array(applications_resp, "items"):
                for item in applications_resp["items"]:
                    app_type = item.get("appType", "")
                    if isinstance(app_type, str) and app_type.endswith("::"):
                        app_type = app_type[:-2]
                    
                    # Get othersTags for additional filtering
                    others_tags = item.get("othersTags", {})
                    
                    # If additional_tags provided, filter applications
                    if additional_tags:
                        match = True
                        for key, values in additional_tags.items():
                            app_tag_values = others_tags.get(key, [])
                            # Check if any of the required values match
                            if not any(v.lower() in [atv.lower() for atv in app_tag_values] for v in values):
                                match = False
                                break
                        
                        if not match:
                            continue  # Skip this application
                    
                    applications.append({
                        "id": item.get("id"),
                        "name": item.get("credentialName"),
                        "appType": app_type,
                        "othersTags": others_tags
                    })
                
                filter_msg = ""
                if additional_tags:
                    filter_msg = f" (filtered by {additional_tags})"
                
                if applications:
                    return {
                        "success": True, 
                        "tag_name": tag_name, 
                        "additional_tags": additional_tags,
                        "applications": applications, 
                        "count": len(applications), 
                        "message": f"Found {len(applications)} applications for tag '{tag_name}'{filter_msg}. User can select an existing application or create new credentials."
                    }
                else:
                    return {
                        "success": False,
                        "tag_name": tag_name,
                        "additional_tags": additional_tags,
                        "applications": [],
                        "count": 0,
                        "message": f"No applications found for tag '{tag_name}'{filter_msg}. User can create new credentials."
                    }
            else:
                return {
                    "success": False,
                    "tag_name": tag_name,
                    "additional_tags": additional_tags,
                    "applications": [],
                    "count": 0,
                    "message": f"No applications found for tag '{tag_name}'. User can create new credentials."
                }

        except Exception as e:
            return {
                "success": False, 
                "tag_name": tag_name,
                "applications": [],
                "count": 0,
                "message": f"Error occurred while fetching applications for tag '{tag_name}': {e}"
            }

    @mcp.tool()
    def fetch_cc_rule_by_id(rule_id: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Fetch rule details by rule id from the **compliancecow**.

        Args:
            rule_id: Rule Id of the rule to retrieve
            
        Returns:
            dict containing complete rule structure and metadata
        """
        
        try:

            rule_response = rule.fetch_cc_rule_by_id(rule_id, ctx)
            logger.debug(f"fetch_cc_rule_by_id: rule_output: {rule_response}\n")

            if len(rule_response) == 0:
                return {
                    "success": False,
                    "rule_id": rule_id,
                    "error": f"Rule '{rule_id}' not found in ComplianceCow. This means the rule is not published or does not exist in ComplianceCow.",
                    "next_actions": ["publish_rule", "cancel"]
                }

            return rule_response
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to fetch rule with id '{rule_id}': {str(e)}",
                "rule_id": rule_id
            }

    @mcp.tool()
    def fetch_cc_rule_by_name(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Fetch rule details by rule name from the **compliancecow**.

        Args:
            rule_name: Rule name of the rule to retrieve
            
        Returns:
            Dict containing complete rule structure and metadata
        """
        
        try:

            rule_response = rule.fetch_cc_rule_by_name(rule_name, ctx)
            logger.debug(f"fetch_cc_rule_by_name: rule_output: {rule_response}\n")

            if len(rule_response) == 0:
                return {
                    "success": False,
                    "rule_name": rule_name,
                    "error": f"Rule '{rule_name}' not found in ComplianceCow. This means the rule is not published or does not exist in ComplianceCow.",
                    "next_actions": ["publish_rule", "cancel"]
                }

            return rule_response
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to fetch rule with id '{rule_name}': {str(e)}",
                "rule_name": rule_name
            }
    
    @mcp.tool()
    def fetch_assessments(categoryId: str = "", categoryName: str = "", assessmentName: str = "", ctx: Context | None = None) -> vo.AssessmentListVO:
        """
        Fetch the list of available assessments in ComplianceCow.  

        TOOL PURPOSE:
        - Retrieves a list of available assessments if no specific match is provided.  
        - Returns only basic assessment info (id, name, category) without the full control hierarchy.  
        - Used to confirm the assessment name while attaching a rule to a specific control.  

        Args:
            categoryId (Optional[str]): Assessment category ID.  
            categoryName (Optional[str]): Assessment category name.  
            assessmentName (Optional[str]): Assessment name.  

        Returns:
            - assessments (list[Assessments]): A list of assessment objects, each containing:  
                - id (str): Unique identifier of the assessment.  
                - name (str): Name of the assessment.  
                - category_name (str): Name of the category.  
            - error (Optional[str]): An error message if any issues occurred during retrieval.  
        """
        try:
            params = {
                "fields": "basic",
                "category_id": categoryId,
                "category_name_contains": categoryName,
                "name_contains": assessmentName
            }

            assessments = rule.get_assessments(params, ctx)
            logger.debug("assessment_output: {}\n".format(assessments))
            return assessments

        except Exception:
            return vo.AssessmentListVO(error="Facing internal error")

    @mcp.tool()
    def fetch_leaf_controls_of_an_assessment(assessment_id: str = "", ctx: Context | None = None) -> Any:
        """
        To fetch the only the **leaf controls** for a given assessment.
        If assessment_id is not provided use other tools to get the assessment and its id.
        
        Args:
            - assessment_id (str, required): Assessment id or plan id.

        Returns:
            - controls (list[AutomatedControlVO]): list of controls
                - id (str): Control ID.
                - displayable (str): Displayable name or label.
                - alias (str): Alias of the control.
                - activationStatus (str): Activation status.
                - ruleName (str): Associated rule name.
                - assessmentId (str): Assessment identifier.
            - error (Optional[str]): An error message if any issues occurred during retrieval.
        """
        try:
            params = {
                "fields": "basic",
                "skip_prereq_ctrl_priv_check": "false",
                "page": 1,
                "page_size": 100,
                "plan_id": assessment_id,
                "is_leaf_control":True
            }
        
            leaf_controls = rule.get_assessment_controls(params, ctx)
            logger.debug(f"leaf_controls_output: {leaf_controls}\n")
            
            if isinstance(leaf_controls, list):
                return leaf_controls
            else:
                return {"error": "Failed to fetch leaf controls"}
        except Exception as e:
            return  {"error": "Failed to fetch leaf controls"}

        
    @mcp.tool()
    def check_applications_publish_status(app_info: list[dict], ctx: Context | None = None) -> dict[str, Any]:
        """
            Check publication status for each application in the provided list.

            app_info structure is [{"name":["ACTUAL application_class_name"]}]
            
            Args:
                app_info: List of application objects to check
                
            Returns:
                Dict with publication status for each application.
                Each app will have 'published' field: True if published, False if not.
        """
        try:
            headers = wsutils.create_header(ctx)
            
            app_resp = wsutils.post(
                path=wsutils.build_api_url(endpoint=constants.URL_FETCH_CC_APPLICATIONS),
                data=json.dumps(app_info),
                header=headers
            )

            if len(app_resp) > 0:
                return {
                    "success": True,
                    "app_info": app_resp
                }
            else:
                return {
                    "success": False,
                    "error": "No application details found",
                    "app_info": []
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to fetch application information: {str(e)}",
                "app_info": []
            }
    
    
    @mcp.tool()
    def check_rule_publish_status(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
            """
            Check if a rule is already published.
    
            - If not published → publish the rule so it becomes available for control attachment  
            - Once published, prompt the user:  
            "Do you want to attach this rule to a ComplianceCow control? (yes/no)"  
            - If yes → ask for assessment name and control alias to proceed with association  
            - If no → end workflow  
    
            Args:
                rule_name: Name of the rule to check
    
            Returns:
                Dict with publication status and details
            """
            try:
                headers = wsutils.create_header(ctx)
                
                # Prepare request data
                request_data = {
                    "ruleName": rule_name,
                    "host": ""
                }
                
                rule_resp = wsutils.post(
                    path=wsutils.build_api_url(endpoint=constants.URL_FETCH_CC_RULES),
                    data=json.dumps(request_data),
                    header=headers
                )
    
                # Check if response has items and if items list is not empty
                if rule_resp and rule_resp.get("items") and len(rule_resp.get("items", [])) > 0:
                    return {
                        "success": True,
                        "published": True,
                        "rule_info": rule_resp.get("items"),
                        "message": f"Rule '{rule_name}' is already published"
                    }
                else:
                    return {
                        "success": True,
                        "published": False,
                        "rule_info": [],
                        "message": f"Rule '{rule_name}' is not published"
                    }
    
            except Exception as e:
                return {
                    "success": False,
                    "published": False,
                    "error": f"Failed to check rule publish status: {str(e)}",
                    "rule_info": []
                }
    
    
    @mcp.tool()
    async def list_assets_cc(ctx: Context | None = None) -> dict:
        """
            Retrieve all available assets (integration plans).
            
            Returns:
                - success (bool): Indicates if the operation completed successfully.
                - assets (list[dict]): A list of assets.
                    - id (str): Asset id.
                    - name (str): Name of the asset.
                - error (Optional[str]): An error message if any issues occurred during retrieval. 
        """
        try:
            logger.info("list_assets: \n")

            output = await utils.make_API_call_to_CCow_and_get_response(constants.URL_ASSETS, "GET", ctx=ctx)
            logger.debug("assets output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))
            
            # Handle error response
            if isinstance(output, str):
                logger.error("list_assets error: {}\n".format(output))
                return {"success": False, "error": output, "assets": []}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("list_assets error: {}\n".format(output))
                    return {"success": False, "error": output, "assets": []}
                
                if "error" in output:
                    logger.error("list_assets error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error", "Facing internal error"), "assets": []}
            
            assets: list[vo.AssetVO] = []
            if isinstance(output, dict) and "items" in output:
                for item in output["items"]:
                    if "name" in item:
                        assets.append(assets_vo.AssetVO.model_validate(item))
            
            logger.debug("modified assets: {}\n".format([asset.model_dump() for asset in assets]))

            return {"success": True, "assets": [asset.model_dump() for asset in assets]}
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("list_assets error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error listing assets: {e}", "assets": []}


    @mcp.tool()
    async def list_checks(assetId: str, ctx: Context | None = None) -> dict:
        """
            Retrieve all checks associated with an asset.
            
            Args:
                - assetId (str): Asset id (plan id).
            
            Returns:
                - success (bool): Indicates if the operation completed successfully.
                - checks (list[dict]): A list of checks.
                    - id (str): Check id.
                    - name (str): Name of the check.
                - error (Optional[str]): An error message if any issues occurred during retrieval. 
        """
        try:
            logger.info("list_checks: assetId: {}\n".format(assetId))

            output = await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_PLANS}/{assetId}/fetch-all-evidences", "POST", ctx=ctx)
            logger.debug("checks output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))
            
            # Handle error response
            if isinstance(output, str):
                logger.error("list_checks error: {}\n".format(output))
                return {"success": False, "error": output, "checks": []}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("list_checks error: {}\n".format(output))
                    return {"success": False, "error": output, "checks": []}
                
                if "error" in output:
                    logger.error("list_checks error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error", "Facing internal error"), "checks": []}
            
            checks = []
            if isinstance(output, dict) and "items" in output:
                for item in output["items"]:
                    if "name" in item and "id" in item:
                        checks.append({"name": item["name"], "id": item["id"], "controlId": item["planControlId"]})
            
            return {"success": True, "checks": checks}
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("list_checks error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error listing checks: {e}", "checks": []}


    @mcp.tool()
    async def get_asset_control_hierarchy(assetId: str, ctx: Context | None = None) -> dict:
        """
            Retrieve the complete control hierarchy for an asset with nested plan controls.
            Returns only id and name for each control while preserving the full hierarchical structure.
            
            Args:
                - assetId (str): Asset id.
            
            Returns:
                - success (bool): Indicates if the operation completed successfully.
                - planControls (list[dict]): Nested hierarchy of controls with only id and name.
                    Each control contains:
                    - id (str): Control id.
                    - name (str): Name of the control.
                    - planControls (list[dict]): Nested child controls (
                - error (Optional[str]): An error message if any issues occurred during retrieval. 
        """
        def extract_control_hierarchy(control: dict) -> dict:
            """
            Recursively extract only id and name from a control and its nested planControls.
            Preserves the hierarchy structure.
            """
            result = {
                "id": control.get("id", ""),
                "name": control.get("name", "")
            }
            
            if "planControls" in control and isinstance(control["planControls"], list) and len(control["planControls"]) > 0:
                result["planControls"] = [extract_control_hierarchy(child) for child in control["planControls"]]
            
            return result
        
        try:
            logger.info("get_asset_control_hierarchy: assetId: {}\n".format(assetId))

            output = await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_PLANS}/{assetId}", "GET", ctx=ctx)
            logger.debug("plan output: {}\n".format(json.dumps(output) if isinstance(output, dict) else output))
            
            if isinstance(output, str):
                logger.error("get_asset_control_hierarchy error: {}\n".format(output))
                return {"success": False, "error": output, "planControls": []}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("get_asset_control_hierarchy error: {}\n".format(output))
                    return {"success": False, "error": output, "planControls": []}
                
                if "error" in output:
                    logger.error("get_asset_control_hierarchy error: {}\n".format(output.get("error")))
                    return {"success": False, "error": output.get("error", "Facing internal error"), "planControls": []}
            
            plan_controls = []
            if isinstance(output, dict) and "planControls" in output and isinstance(output["planControls"], list):
                for control in output["planControls"]:
                    plan_controls.append(extract_control_hierarchy(control))
            
            logger.debug("modified plan controls hierarchy: {}\n".format(json.dumps(plan_controls, indent=2)))

            return {"success": True, "planControls": plan_controls}
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("get_asset_control_hierarchy error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error getting asset control hierarchy: {e}", "planControls": []}


    @mcp.tool()
    async def list_asset_schedules( assetId: str, ctx: Context | None = None) -> dict:
        """
        List schedules for a given asset.

        Args:
            - assetId (str): Asset ID whose schedules need to be listed

        Returns:
            - success (bool)
            - items (list): list of schedules
            - error (Optional[str])
        """
        try:
            logger.info("list_asset_schedules: assetId: %s", assetId)

            if not assetId or not str(assetId).strip():
                return {
                    "success": False,
                    "error": "assetId is mandatory and cannot be empty",
                }

            payload = {
                "assessmentId": str(assetId).strip()
            }

            output = await utils.make_GET_API_call_to_CCow_With_Payload(constants.URL_ASSESSMENT_SCHEDULE, payload, ctx=ctx)

            logger.debug(
                "list_asset_schedules raw output: %s",
                json.dumps(output) if isinstance(output, dict) else output,
            )

            if isinstance(output, str):
                return {"success": False, "error": output}

            if isinstance(output, dict):
                if "Message" in output:
                    return {"success": False, "error": output}

                if "error" in output:
                    return {"success": False, "error": output.get("error")}

            items = output.get("items", [])
            filtered_items = []

            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    filtered_items.append(
                        {
                            "id": item.get("id"),
                            "name": item.get("name"),
                            "description": item.get("description"),
                            "controlPeriod": item.get("controlPeriod"),
                            "cronTab": item.get("cronTab"),
                            "status": item.get("status"),
                        }
                    )

            return {
                "success": True,
                "items": filtered_items,
            }

        except Exception as e:
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "error": f"Unexpected error listing schedules: {e}",
            }


    @mcp.tool()
    def verify_control_automation(control_id: str, ctx: Optional[Context] = None) -> dict[str, Any]:
        """
        Verify if a control is automated or not based on the presence of ruleId.
        If ruleId exists, fetch and return basic rule information.
        
        Args:
            control_id: The ID of the control to verify
            
        Returns:
            Dictionary containing automation status and rule details if automated
        """
        headers = wsutils.create_header(ctx)
        
        try:
            # Fetch control details
            control_response = wsutils.get(
                path=wsutils.build_api_url(endpoint=f"{constants.URL_PLAN_CONTROLS}/{control_id}"),
                header=headers
            )
            
            if isinstance(control_response, str) or (isinstance(control_response, dict) and "error" in control_response):
                return {
                    "error": "Unable to retrieve control details",
                    "control_id": control_id,
                    "automated": False
                }
            
            # Check if ruleId exists
            rule_id = control_response.get("ruleId")
            
            if not rule_id:
                return {
                    "control_id": control_id,
                    "control_name": control_response.get("name", "Unknown"),
                    "automated": False,
                    "message": "This control is not automated. No rule is associated with it."
                }
            
            # Control is automated, fetch rule details
            try:
                rule_details = fetch_cc_rule_by_id(rule_id, ctx)
                
                if isinstance(rule_details, dict) and "error" not in rule_details:
                    return {
                        "control_id": control_id,
                        "control_name": control_response.get("name", "Unknown"),
                        "automated": True,
                        "rule_id": rule_id,
                        "rule_info": {
                            "name": rule_details.get("name", "Unknown"),
                            "type": rule_details.get("type", "Unknown"),
                            "description": rule_details.get("meta", {}).get("description", "No description available"),
                        },
                        "message": "This control is automated with the rule details provided above."
                    }
                else:
                    return {
                        "control_id": control_id,
                        "control_name": control_response.get("name", "Unknown"),
                        "automated": True,
                        "rule_id": rule_id,
                        "message": "Control is automated but unable to fetch rule details.",
                        "error": rule_details.get("error", "Unknown error")
                    }
                    
            except Exception as e:
                return {
                    "control_id": control_id,
                    "control_name": control_response.get("name", "Unknown"),
                    "automated": True,
                    "rule_id": rule_id,
                    "message": "Control is automated but error occurred while fetching rule details.",
                    "error": str(e)
                }
                
        except Exception as e:
            return {
                "error": f"Failed to verify control automation: {str(e)}",
                "control_id": control_id,
                "automated": False
            }

    @mcp.tool()
    def fetch_cc_rules_list(params: dict[str, Any] = None, ctx: Optional[Context] = None) -> list[vo.SimplifiedRuleVO]:
        """
        Fetch list of CC rules with only name, description, and id.
        This tool should ONLY be used for attaching rules to control flows.
        
        Args:
            params: Optional query parameters for filtering/pagination
                - name_contains: Filter rules by name containing this string
                - page_size: Number of items to be returned (default 100)
            
        Returns:
            List of simplified rule objects containing only name, description, and id
        """
        if params is None:
            params = {}
        
        if not rule.is_valid_key(params, "page_size"):
            params["page_size"] = 100
        
        headers = wsutils.create_header(ctx)
        cur_page = 1
        has_next = True
        combined_rules = []
        
        while has_next:
            paginated_params = {**params, "page": cur_page}
            
            try:
                response = wsutils.get(
                    path=wsutils.build_api_url(endpoint=constants.URL_GET_CC_RULE),
                    params=paginated_params,
                    header=headers
                )
                
                if rule.is_valid_key(response, "items", array_check=True):
                    rules = response["items"]
                    
                    for rule_data in rules:
                        # Extract only name, description, and id
                        simplified_rule = {
                            "id": rule_data.get("id"),
                            "name": rule_data.get("name"),
                            "description": rule_data.get("meta", {}).get("description", "No description available")
                        }
                        combined_rules.append(simplified_rule)
                    
                    total_pages = int(response.get("totalPage", 0)) or 1
                    cur_page += 1
                    has_next = cur_page <= total_pages
                else:
                    has_next = False
                    
            except Exception as e:
                return [{
                    "error": f"Failed to fetch CC rules list: {str(e)}"
                }]
        
        return combined_rules

    @mcp.tool()
    async def list_control_notes(
        controlId: str,
        ctx: Context | None = None
    ) -> dict:
        """
        List all notes for a given control.
        
        This tool retrieves all notes associated with a control.
        
        Args:
            controlId (str): The control ID to list notes for (required).
        
        Returns:
            Dict with success status and notes:
            - success (bool): Whether the request was successful
            - notes (list[dict]): list of note objects, each containing:
                - id (str): Note ID
                - topic (str): Note topic
                - notes (str): Note content
            - totalCount (int): Total number of notes found
            - error (str, optional): Error message if request failed
        """
        try:
            logger.info("list_control_notes: \n")
            
            if not controlId or not str(controlId).strip():
                logger.error("list_control_config_notes error: controlId is mandatory\n")
                return {"success": False, "error": "controlId is mandatory"}

            control_id = str(controlId).strip()
            url = constants.URL_PLAN_CONTROL_NOTES.format(controlConfigId=control_id)
            
            logger.debug("list_control_notes URL: {}\n".format(url))
            
            output = await utils.make_GET_API_call_to_CCow(url, ctx=ctx)
            
            logger.info(f"create_control_note: \n Response : {output}\n")

            if isinstance(output, str) or (isinstance(output, dict) and "error" in output):
                logger.error("list_control_notes error: {}\n".format(output))
                return {"success": False, "error": "Failed to fetch control notes"}
            
            if isinstance(output, dict):
                if "Message" in output:
                    logger.error("list_control_notes error: {}\n".format(output))
                    return {"success": False, "error": output}
                
                items = output.get("items", [])
                if not isinstance(items, list):
                    items = []

                abstracted_items = []
                for item in items:
                    if isinstance(item, dict):
                        abstracted_item = {
                            "id": item.get("id", ""),
                            "topic": item.get("topic", ""),
                            "notes": item.get("notes", ""),
                        }
                        abstracted_items.append(abstracted_item)
                
                logger.info(f"list_control_notes: {abstracted_items} \n Found {len(abstracted_items)} note(s)\n")
                return {"success": True, "notes": abstracted_items, "totalCount": len(abstracted_items)}
            
            logger.error("list_control_notes error: Unexpected response type: {}\n".format(type(output)))
            return {"success": False, "error": f"Unexpected response type: {output}"}
            
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error("list_control_config_notes error: {}\n".format(e))
            return {"success": False, "error": f"Unexpected error listing control notes: {e}"}



@mcp.tool()
def get_tasks_summary(ctx: Context | None = None) -> str:
    """
    Resource containing minimal task information for initial selection.
    
    This tool is also used as a fallback resource when fetch_tasks_suggestions is disabled or does not return suitable matches, ensuring
    the user always has access to a broader list of available tasks for manual selection.

    This resource provides only the essential information needed for task selection:
    - Task name and display name
    - Brief description
    - Purpose and capabilities
    - Tags for categorization
    - Inputs/Outputs params with minimal details
    - Basic README summary

    Use this for initial task discovery and selection. Detailed information can be
    retrieved later using `tasks://details/{task_name}` for selected tasks only.

    AUTOMATIC OUTPUT ANALYSIS BY INTENTION:
    - MANDATORY: Analyze each task's output purpose and completion level during selection
    - IDENTIFY output intentions that require follow-up processing:
        * SPLITTING INTENTION: Outputs that divide data into separate categories → REQUIRE consolidation
        * EXTRACTION INTENTION: Outputs that pull raw data without formatting → REQUIRE transformation  
        * VALIDATION INTENTION: Outputs that check compliance without final reporting → REQUIRE analysis/reporting
        * PROCESSING INTENTION: Outputs that transform data but don't create final deliverables → REQUIRE finalization

    OUTPUT COMPLETION ASSESSMENT:
    - EVALUATE: Does this output serve as a final deliverable for end users?
    - ASSESS: Is this output consumable without additional processing?
    - DETERMINE: Does this output require combination with other outputs to be meaningful?
    - IDENTIFY: Is this output an intermediate step in a larger workflow?

    WORKFLOW COMPLETION ENFORCEMENT:
    - NEVER present task selections that end with intermediate processing outputs
    - AUTOMATICALLY suggest tasks that fulfill incomplete intentions
    - ENSURE every workflow produces actionable final deliverables
    - RECOMMEND tasks that bridge gaps between current outputs and user goals

    Mandatory functionality:
    - Retrieve a list of task summaries based on the user's request
    - Analyze task outputs and suggest additional tasks for workflow completion
    - If no matching task is found for the requested functionality, prompt user for confirmation
    - Based on user response, either proceed accordingly or create support ticket using create_support_ticket()

    """

    try:
        available_tasks = []
        tasks_resp = rule.fetch_task_api(params={
            "tags": "primitive"}, ctx=ctx)

        if rule.is_valid_key(tasks_resp, "items", array_check=True):
            available_tasks = [TaskVO.from_dict(
                task) for task in tasks_resp["items"]]

        if not available_tasks:
            return json.dumps({"error": "No tasks loaded", "tasks": []})

        tasks_summary = []
        for task in available_tasks:
            # Decode readme for capabilities only
            readme_content = rule.decode_content(task.readmeData)
            capabilities = rule.extract_capabilities_from_readme(
                readme_content)
            
            inputs = [{"name":input.name,"description":input.description} for input in task.inputs]
            outputs = [{"name":output.name,"description":output.description} for output in task.outputs]


            # Minimal info for selection
            task_summary = {"name": task.name, "displayName": task.displayName, "description": task.description, "purpose": rule.extract_purpose_from_description(task.description), "tags": task.tags, "capabilities": capabilities, "input_params":inputs, "output_params": outputs, "has_templates": any(inp.templateFile for inp in task.inputs), "app_type": task.appTags.get("appType", ["generic"])[0] if task.appTags.get("appType") else "generic"}
            tasks_summary.append(task_summary)

        return json.dumps({"total_tasks": len(tasks_summary), "tasks": tasks_summary, "message": f"Found {len(tasks_summary)} available tasks - use tasks://details/{{task_name}} for full details", "categories": rule.categorize_tasks_by_tags(tasks_summary)}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"An error occurred while fetching the task summary: {e}", "tasks": []})


@mcp.tool()
def get_template_guidance(task_name: str, input_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """Get detailed guidance for filling out a template-based input.

    COMPLETE TEMPLATE HANDLING PROCESS:

    STEP 1 - TEMPLATE IDENTIFICATION:
    - Called for inputs that have a templateFile property
    - Provides decoded template content and structure explanation
    - Returns required fields, format-specific tips, and validation rules

    PREFILLING PROCESS:
    1. Analyze template structure for external dependencies
    2. Prefill template with realistic values based on the instructions

    RELEVANCE FILTERING:
    - ANALYZE task description and user use case to create targeted search queries
    - EXTRACT key terms from rule purpose and task capabilities
    - COMBINE system name with specific functionality being configured
    - PRIORITIZE documentation that matches the exact use case scenario

    STEP 3 - ENHANCED TEMPLATE PRESENTATION TO USER:
    Show the template with this EXACT format:
    "Now configuring: [X of Y inputs]

    Task: {task_name}
    Input: {input_name} - {description}

    You can:
    - Accept these prefilled values (type 'accept')
    - Modify specific sections (provide your modifications)
    - Replace entirely (provide your complete configuration)

    Please review and confirm or modify the prefilled configuration:"

    STEP 4 - FALLBACK TO ORIGINAL TEMPLATE:
    If no documentation found or prefilling fails:
    - Show original empty template with standard format
    - Include note: "No documentation found for prefilling. Please provide your configuration."
    - Continue with existing workflow

    STEP 5 - COLLECT USER CONTENT:
    - Wait for the user to provide their response (accept/modify/replace)
    - Handle "accept" by using prefilled content
    - Handle modifications by merging with prefilled baseline
    - Handle complete replacement with user content
    - Do NOT proceed until the user provides content
    - NEVER use template content as default values without documentation analysis

    STEP 6 - PROCESS TEMPLATE INPUT:
    - Call collect_template_input(task_name, input_name, user_content)
    - Include documentation source metadata
    - Validates content format, checks required fields, uploads file
    - Returns file URL for use in rule structure

    TEMPLATE FORMAT HANDLING:
    - JSON: Must be valid JSON with proper brackets and quotes
    - TOML: Must follow TOML syntax with proper sections [section_name]
    - YAML: Must have correct indentation and structure
    - XML: Must be well-formed XML with proper tags

    VALIDATION RULES:
    - Format-specific syntax validation
    - Required field presence checking
    - Data type validation where applicable
    - Template structure compliance
    - Documentation standard compliance (when applicable)

    CRITICAL TEMPLATE RULES:
    - ALWAYS call get_template_guidance() for inputs with templates
    - ALWAYS analyze documentation before showing template to user
    - ALWAYS show the prefilled template (or original if no docs found) with exact presentation format
    - ALWAYS wait for the user to provide response (accept/modify/replace)
    - ALWAYS call collect_template_input() to process user content
    - NEVER use template content directly - always use documentation-enhanced or user-provided content
    - ALWAYS use returned file URLs in rule structure

    PROGRESS TRACKING:
    - Show "Now configuring: [X of Y inputs]" for user progress
    - Include clear task and input identification
    - Provide format-specific guidance and tips
    - Include documentation analysis results and source citations

    Args:
        task_name: Name of the task
        input_name: Name of the input that has a template

    Returns:
        Dict containing template content, documentation analysis, prefilled values, and guidance
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

        if not task_input.templateFile:
            return {"success": False, "error": f"Input {input_name} does not have a template file"}

        # Decode template and provide guidance
        decoded_template = rule.decode_content(task_input.templateFile)
        guidance = rule.generate_detailed_template_guidance(
            decoded_template, task_input)

        return {"success": True, "task_name": task_name, "input_name": input_name, "input_description": task_input.description, "format": task_input.format, "decoded_template": decoded_template, "guidance": guidance, "example_content": rule.generate_example_content(decoded_template, task_input.format), "validation_rules": rule.get_template_validation_rules(task_input.format), "presentation_format": f"Now configuring: [X of Y inputs]\n\nTask: {task_name}\nInput: {input_name} - {task_input.description}\n\nHere's the template structure:\n\n{decoded_template}\n\nThis {task_input.format} file requires specific fields. Please provide your actual configuration following this template."}

    except Exception as e:
        return {"success": False, "error": f"Failed to get template guidance: {e}"}


@mcp.tool()
def verify_collected_inputs(collected_inputs: dict[str, Any], ctx: Context | None = None) -> dict[str, Any]:
    """Verify all collected inputs with user before rule creation.

    MANDATORY VERIFICATION STEP (Enhanced):

    This tool MUST be called after all inputs are collected but before final rule completion.
    It presents a comprehensive summary of all collected inputs for user verification.

    ENHANCED WITH AUTOMATIC RULE FINALIZATION:
    After user confirms verification, this tool can automatically finalize the rule by:
    1. Building complete I/O mapping based on task sequence and inputs
    2. Adding mandatory compliance outputs 
    3. Setting rule status to ACTIVE
    4. Completing the rule creation process

    HANDLES DUPLICATE INPUT NAMES WITH TASK ALIASES (Preserved):
    - Uses unique identifiers (TaskAlias.InputName) for each input
    - Properly maps each unique input to its specific task alias
    - Creates structured inputs for rule creation with unique names when needed
    - Maintains clear separation between inputs from different task instances

    VERIFICATION REQUIREMENTS (Preserved):
    1. Show complete summary of ALL collected inputs with unique IDs
    2. Display both template files and parameter values
    3. Show file URLs for uploaded templates
    4. Present clear verification checklist
    5. Get explicit user confirmation
    6. Allow user to modify values if needed
    7. Prepare inputs for rule structure creation with proper task alias mapping
    8. NEW: Automatically finalize rule after user confirmation

    VERIFICATION PRESENTATION FORMAT (Preserved):
    "INPUT VERIFICATION SUMMARY:

    Please review all collected inputs before rule creation:

    TEMPLATE INPUTS (Uploaded Files):
    ✓ Task Input: [TaskAlias.InputName]
        Task: [TaskAlias] ([TaskName]) → Input: [InputName]
        Format: [Format]
        File: [filename]
        URL: [file_url]
        Size: [file_size] bytes
        Status: ✓ Validated

    PARAMETER INPUTS (Values):
    ✓ Task Input: [TaskAlias.InputName]
        Task: [TaskAlias] ([TaskName]) → Input: [InputName]
        Type: [DataType]
        Value: [user_value]
        Required: [Yes/No]
        Status: ✓ Set

    VERIFICATION CHECKLIST:
    □ All required inputs collected
    □ Template files uploaded and validated
    □ Parameter values set and confirmed
    □ No missing or invalid inputs
    □ Ready for rule creation

    Are all these inputs correct?
    - Type 'yes' to proceed with rule creation
    - Type 'modify [TaskAlias.InputName]' to change a specific input
    - Type 'cancel' to abort rule creation"

    CRITICAL VERIFICATION RULES (Enhanced):
    - NEVER proceed to final rule creation without user verification
    - ALWAYS show complete input summary with unique identifiers
    - ALWAYS get explicit user confirmation
    - Allow input modifications using unique IDs
    - Validate completeness before approval
    - Prepare structured inputs for rule creation with proper task mapping
    - NEW: Automatically finalize rule with I/O mapping after confirmation

    Args:
        collected_inputs: dict containing all collected template files and parameter values with unique IDs

    Returns:
        Dict containing verification status, user confirmation, and structured inputs for rule finalization
    """

    if not collected_inputs:
        return {"success": False, "error": "No inputs provided for verification"}

    try:
        # Analyze collected inputs with unique ID handling (preserved logic)
        verification_summary = {
            "template_files": [], 
            "parameter_values": [], 
            "total_collected": 0, 
            "missing_inputs": [], 
            "validation_errors": [], 
            "structured_inputs": {}, 
            "inputs_meta": [],
            "task_input_mapping": {},  # Maps rule input names to original task inputs
            "task_alias_map": collected_inputs.get("task_alias_map", {})  # Preserve task alias mapping
        }

        # Process template files with unique IDs (preserved processing)
        template_files = collected_inputs.get("template_files", {})
        for unique_input_id, file_info in template_files.items():
            # Parse unique_input_id: "TaskAlias.InputName"
            if "." not in unique_input_id:
                continue  # Skip invalid IDs

            task_alias, input_name = unique_input_id.split(".", 1)

            verification_summary["template_files"].append({
                "unique_input_id": unique_input_id,
                "task_alias": task_alias,
                "task_name": file_info.get("task_name", ""),
                "input_name": input_name,
                "filename": file_info.get("filename"),
                "file_url": file_info.get("file_url"),
                "file_size": file_info.get("file_size"),
                "format": file_info.get("format"),
                "data_type": file_info.get("data_type", "FILE"),
                "status": "✓ Validated" if file_info.get("validated") else "⚠ Needs validation"
            })

            # For rule creation: Handle input naming strategy
            input_value = file_info.get("file_url")
            
            # Check if this input name already exists in structured_inputs
            if input_name in verification_summary["structured_inputs"]:
                # Conflict detected - use unique naming: TaskAlias_InputName
                rule_input_name = f"{task_alias}_{input_name}"
            else:
                # No conflict - use original input name
                rule_input_name = input_name
                
            verification_summary["structured_inputs"][rule_input_name] = input_value

            verification_summary["inputs_meta"].append({
                "name": rule_input_name,
                "dataType": file_info.get("data_type", "FILE"),
                "required": file_info.get("required", True),
                "defaultValue": input_value,
                "format": file_info.get("format")
            })

            # Store mapping for I/O map creation
            verification_summary["task_input_mapping"][rule_input_name] = {
                "task_alias": task_alias,
                "task_name": file_info.get("task_name", ""),
                "input_name": input_name,
                "unique_id": unique_input_id,
                "rule_input_name": rule_input_name
            }

        # Process parameter values with unique IDs (preserved processing)
        parameter_values = collected_inputs.get("parameter_values", {})
        for unique_input_id, value_info in parameter_values.items():
            # Parse unique_input_id: "TaskAlias.InputName"
            if "." not in unique_input_id:
                continue  # Skip invalid IDs

            task_alias, input_name = unique_input_id.split(".", 1)

            verification_summary["parameter_values"].append({
                "unique_input_id": unique_input_id,
                "task_alias": task_alias,
                "task_name": value_info.get("task_name", ""),
                "input_name": input_name,
                "value": value_info.get("value"),
                "data_type": value_info.get("data_type"),
                "required": value_info.get("required"),
                "status": "✓ Set" if value_info.get("value") is not None else "⚠ Missing"
            })

            # For rule creation: Handle input naming strategy
            input_value = value_info.get("value")
            
            # Check if this input name already exists in structured_inputs
            if input_name in verification_summary["structured_inputs"]:
                # Conflict detected - use unique naming: TaskAlias_InputName
                rule_input_name = f"{task_alias}_{input_name}"
            else:
                # No conflict - use original input name
                rule_input_name = input_name
                
            verification_summary["structured_inputs"][rule_input_name] = input_value

            verification_summary["inputs_meta"].append({
                "name": rule_input_name,
                "dataType": value_info.get("data_type", "STRING"),
                "required": value_info.get("required", True),
                "defaultValue": input_value
            })

            # Store mapping for I/O map creation
            verification_summary["task_input_mapping"][rule_input_name] = {
                "task_alias": task_alias,
                "task_name": value_info.get("task_name", ""),
                "input_name": input_name,
                "unique_id": unique_input_id,
                "rule_input_name": rule_input_name
            }

        verification_summary["total_collected"] = len(template_files) + len(parameter_values)

        # Check for missing required inputs
        for item in verification_summary["template_files"] + verification_summary["parameter_values"]:
            if "Missing" in item["status"] or "⚠" in item["status"]:
                verification_summary["missing_inputs"].append(item["unique_input_id"])

        # Generate verification presentation (preserved)
        verification_text = rule.generate_verification_presentation_with_unique_ids(verification_summary)

        return {
            "success": True,
            "verification_summary": verification_summary,
            "verification_presentation": verification_text,
            "ready_for_creation": len(verification_summary["missing_inputs"]) == 0,
            "missing_count": len(verification_summary["missing_inputs"]),
            "structured_inputs": verification_summary["structured_inputs"],
            "inputs_meta": verification_summary["inputs_meta"],
            "task_input_mapping": verification_summary["task_input_mapping"],
            "task_alias_map": verification_summary["task_alias_map"],
            "rule_finalization_ready": True,  # NEW: Ready for automatic rule finalization
            "message": "Input verification prepared with task aliases. Present to user for confirmation, then automatically finalize rule.",
            "next_action": "Show verification_presentation to user and wait for confirmation, then finalize rule"
        }

    except Exception as e:
        return {"success": False, "error": f"Failed to verify collected inputs: {e}"}


@mcp.tool()
def fetch_rule_design_notes(rule_name: str, ctx: Context | None = None) -> dict[str,Any]:
    """
    Fetch and manage design notes for a rule.

    WORKFLOW:

    1. CHECK EXISTING NOTES:
    - Always check if design notes exist for the rule first (whether user wants to create or view)
    - If found: Present complete notebook to user in readable format
    - If not found: Offer to create new ones

    2. IF NOTES EXIST:
    - Show complete notebook with all sections (this serves as the VIEW)
    - Ask: "Here are your design notes. Modify or regenerate?"

    3. USER OPTIONS:
    - MODIFY: 
    1. Ask "Do you need any changes to the design notes?"
    2. If no changes needed: Get user confirmation, then call create_design_notes() to update
    3. If changes needed: Collect modifications, show preview, get confirmation, then call create_design_notes() to update
    - REGENERATE: 
    1. Generate the design notes using generate_design_notes_preview()
    2. Show preview to user
    3. Get user confirmation
    4. If confirmed: Call create_design_notes() to save the regenerated design notes
    - CANCEL: End workflow

    4. IF NO NOTES EXIST:
    - Inform user no design notes found
    - Ask: "Create comprehensive design notes for this rule?"
    - If yes: Generate the design notes using generate_design_notes_preview()
    - Show preview to user
    - Get user confirmation
    - If confirmed: Call create_design_notes() to generate

    KEY RULES:
    - MUST follow this workflow explicitly step by step
    - Always check for existing notes first whenever user asks about design notes (create or view)
    - ALWAYS get user confirmation before calling create_design_notes()
    - If any updates needed, explicitly call create_design_notes() tool to save changes
    - Present notes in Python notebook format
    - Use create_design_notes() for creation and updates

    Args:
        rule_name: Name of the rule

    Returns:
        Dict with success status, rule name, design notes content, and error details
    """

    try:
        headers = wsutils.create_header(ctx)
        payload = {
            "ruleName": rule_name,
            "type": "mcp"
        }
        design_notes_resp = wsutils.post(
            path=wsutils.build_api_url(endpoint=constants.URL_FETCH_DESIGN_NOTES),
            data=json.dumps(payload),
            header=headers
        )

        filename = design_notes_resp.get("fileName")
        design_notes_content = design_notes_resp.get("designNotesContent")
       

        if isinstance(design_notes_content,str) and design_notes_content!="":
            return {
                "success": True,
                "rule_name": rule_name,
                "filename": filename,
                "designNotesContent": rule.decode_content(design_notes_content),
                "message": f"Design notes successfully retrieved for rule {rule_name}. Displaying content to user."
            }
        else:
            return{
                "success": False,
                "rule_name": rule_name,
                "message": f"Design notes not found for rule {rule_name}. Offer to create comprehensive design notes."
            }
        
    except Exception as e:
        return {
            "success": False,
            "rule_name": rule_name,
            "message": f"Error fetching design notes for rule {rule_name}: {e}."
        }


@mcp.tool()
def get_application_info(tag_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Get detailed information about an application, including supported credential types.

    APPLICATION CREDENTIAL CONFIGURATION WORKFLOW:

    1. User selects "Configure new application credentials".
    2. Call this tool to retrieve application details and supported credential types.
    3. Present credential options to the user with:
       - Required attributes
       - Data type
       - If type is bytes → must be Base64-encoded
    4. Collect credential values for the selected type.
    5. Validate that all required attributes are provided.
    6. Verify that each credential value matches its expected data type.
    7. Build the credential configuration and append it to the `apps_config` array.

    DATA VALIDATION REQUIREMENTS:
    - All required attributes must be present.
    - Data type must match specification.
    - Bytes values must be Base64-encoded before saving.

    Args:
        tag_name: The app tag name for retrieving application information

    Returns:
        Dict containing application details and supported credential types
    """
    try:
        header = wsutils.create_header(ctx)

        params = {"appType": tag_name}

        app_resp = wsutils.get(
            path=wsutils.build_api_url(endpoint=constants.URL_FETCH_APPLICATION_CREDENTIALS), 
            params=params, 
            header=header
        )

        if rule.is_valid_array(app_resp, "items"):
            app_info = app_resp["items"][0]
            supported_creds = app_info.get("supportedCreds")
            return {
                "success": True, 
                "app_name": tag_name,
                "supportedCreds": supported_creds,
                "message": f"Retrieved information for application '{tag_name}'. User can select credential type and provide values."
            }
        else:
            return {
                "success": False, 
                "app_name": tag_name,
                "message": f"No credential information found for application '{tag_name}'."
            }

    except Exception as e:
        return {
            "success": False, 
            "app_name": tag_name,
            "message": f"Error occurred while fetching application info for '{tag_name}': {e}"
        }


@mcp.tool()
def fetch_applications(ctx: Context | None = None) -> dict[str, Any]:
    """ 
    Fetch all available applications from the system.
    
    Returns:
        Dict containing list of applications with their details
    """
    try:
        applications = []
        headers = wsutils.create_header(ctx)
        
        get_app_resp = wsutils.get(
            path=wsutils.build_api_url(endpoint=constants.URL_FETCH_APPLICATIONS),
            header=headers
        )
        
        # Add null safety
        items = get_app_resp.get("items", [])
        if not items:
            return {
                "success": True,
                "applications": [],
                "message": "No applications found"
            }
        
        for item in items:
            meta = item.get("meta", {})
            labels = meta.get("labels", {})
            app_types = labels.get("appType", [])
            
            # Skip if no appType available
            if not app_types:
                continue
                
            applications.append({
                "application_class_name": meta.get("name", "Unknown"),
                "app_type": app_types[0]
            })

        return {
            "success": True,
            "applications": applications
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to fetch applications: {str(e)}",
            "applications": []
        }

@mcp.tool()
def check_rule_status(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
    """
    Quick status check showing what's been collected and what's missing.
    Perfect for resuming in new chat windows.

    ENHANCED WITH AUTO-INFERENCE STATUS ANALYSIS:
    - Ignores stored status/phase fields and analyzes actual rule structure
    - Auto-detects completion status based on rule content (same logic as create_rule)
    - Calculates real-time progress percentage from actual components
    - Determines next actions based on what's actually missing
    - Provides accurate resumption guidance regardless of stored metadata
    - Perfect for cross-chat resumption with reliable state detection

    AUTO-INFERENCE LOGIC:
    - Analyzes spec.tasks, spec.inputs, spec.inputsMeta__, spec.ioMap, spec.outputsMeta__
    - Calculates completion based on actual content, not stored fields
    - Determines status: DRAFT → READY_FOR_CREATION → ACTIVE
    - Provides accurate progress: 5% → 25% → 85% → 100%
    - Identifies exactly what components are missing

    Args:
        rule_name: Name of the rule to check status for

    Returns:
        Dict with auto-inferred status information and accurate next action recommendations
    """
    
    try:
        current_rule = fetch_rule(rule_name, ctx)
        if not current_rule["success"]:
            return {
                "success": False, 
                "error": f"Rule '{rule_name}' not found. Start new rule creation?",
                "suggested_action": "create_new_rule"
            }
        
        rule_structure = current_rule["rule_structure"]
        meta = rule_structure.get("meta", {})
        spec = rule_structure.get("spec", {})
        
        # AUTO-INFERENCE: Analyze actual rule structure content (same logic as create_rule)
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
        
        # Real-time completion analysis based on actual content
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
            "outputs_count": len(outputs_meta)
        }
        
        # AUTO-DETECT status and progress - FIXED LOGIC
        if (completion_analysis["has_io_mapping"] and 
            completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"] and 
            completion_analysis["has_tasks"] and
            completion_analysis["has_mandatory_outputs"] and
            completion_analysis["inputs_match_metadata"]):
            # Rule is complete
            inferred_status = "ACTIVE"
            inferred_phase = "completed"
            progress_percentage = 100
            
        elif completion_analysis["has_tasks"]:
            if completion_analysis["inputs_collected"] == completion_analysis["inputs_meta_count"]:
                # ALL inputs collected - ready for finalization
                inferred_status = "READY_FOR_CREATION"
                inferred_phase = "inputs_collected" 
                progress_percentage = 85
            elif completion_analysis["inputs_collected"] > 0:
                # SOME inputs collected - still collecting
                inferred_status = "DRAFT"
                inferred_phase = "collecting_inputs"
                # Calculate actual progress based on collected vs total
                input_progress = (completion_analysis["inputs_collected"] / max(completion_analysis["inputs_meta_count"], 1)) * 60
                progress_percentage = min(25 + int(input_progress), 85)
            elif completion_analysis["has_inputs_meta"]:
                # Tasks defined, inputs metadata exists but no values collected yet
                inferred_status = "DRAFT"
                inferred_phase = "collecting_inputs"
                progress_percentage = 30  # Slightly higher since metadata is prepared
            else:
                # Tasks defined but no inputs yet
                inferred_status = "DRAFT"
                inferred_phase = "tasks_selected"
                progress_percentage = 25
        else:
            # No tasks defined yet
            inferred_status = "DRAFT"
            inferred_phase = "initialized"
            progress_percentage = 5

        # Determine what's missing and next actions based on inferred state - FIXED LOGIC
        missing_components = []
        if not completion_analysis["has_tasks"]:
            missing_components.append("task_selection")
        if completion_analysis["inputs_collected"] < completion_analysis["inputs_meta_count"]:
            missing_components.append("input_collection")
        if not completion_analysis["has_io_mapping"]:
            missing_components.append("io_mapping")
        if not completion_analysis["has_mandatory_outputs"]:
            missing_components.append("mandatory_outputs")

        # Determine next action based on inferred state
        if inferred_status == "ACTIVE":
            next_action = "rule_complete"
            message = f"✅ Rule '{rule_name}' is complete and ready to use!"
            available_actions = ["execute_rule", "create_design_notes", "create_readme", "view_rule"]
            
        elif inferred_status == "READY_FOR_CREATION":
            next_action = "ready_for_finalization"
            message = f"🎯 Rule '{rule_name}' has all {completion_analysis['inputs_collected']} inputs collected. Ready for I/O mapping and finalization."
            available_actions = ["finalize_rule", "verify_inputs", "view_yaml_preview"]
            
        elif inferred_phase == "tasks_selected":
            next_action = "need_input_collection"
            message = f"📋 Rule '{rule_name}' has {completion_analysis['tasks_count']} tasks defined. Ready to collect inputs."
            available_actions = ["start_input_collection", "view_input_overview"]
            
        elif inferred_phase == "collecting_inputs":
            # FIXED: Use actual inputs_meta_count instead of estimation
            remaining = max(0, completion_analysis["inputs_meta_count"] - completion_analysis["inputs_collected"])
            next_action = "continue_input_collection"
            message = f"⏳ Rule '{rule_name}' input collection in progress: {completion_analysis['inputs_collected']} collected, {remaining} remaining. Continue where you left off."
            available_actions = ["continue_collecting_inputs", "view_collected_inputs", "input_overview"]
            
        elif inferred_phase == "initialized":
            next_action = "need_task_selection"
            message = f"🚀 Rule '{rule_name}' is initialized. Need to select tasks to continue."
            available_actions = ["select_tasks", "view_rule_info"]
            
        else:
            next_action = "unknown_state"
            message = f"❓ Rule '{rule_name}' is in unknown state. Manual review may be needed."
            available_actions = ["view_rule_details", "restart_creation"]

        # Estimate remaining time based on what's missing - FIXED LOGIC
        if inferred_status == "ACTIVE":
            estimated_time = "Complete"
        elif inferred_status == "READY_FOR_CREATION":
            estimated_time = "~5 minutes (I/O mapping and finalization)"
        elif completion_analysis["has_tasks"]:
            remaining_inputs = max(0, completion_analysis["inputs_meta_count"] - completion_analysis["inputs_collected"])
            estimated_time = f"~{remaining_inputs * 2 + 5} minutes ({remaining_inputs} inputs + finalization)"
        else:
            estimated_time = "~15-20 minutes (full setup needed)"

        # Build comprehensive status info based on auto-inference
        status_info = {
            "rule_name": rule_name,
            "inferred_status": inferred_status,  # Auto-detected, not from stored field
            "inferred_phase": inferred_phase,    # Auto-detected, not from stored field
            "progress_percentage": progress_percentage,  # Calculated from actual content
            "missing_components": missing_components,
            "has_tasks": completion_analysis["has_tasks"],
            "has_inputs": completion_analysis["has_inputs"],
            "has_inputs_meta": completion_analysis["has_inputs_meta"],
            "inputs_match_metadata": completion_analysis["inputs_match_metadata"],
            "outputs_count": completion_analysis["outputs_count"],
            "tasks_defined": completion_analysis["tasks_count"],
            "inputs_collected": completion_analysis["inputs_collected"],
            "inputs_metadata_count": completion_analysis["inputs_meta_count"],
            "has_io_mapping": completion_analysis["has_io_mapping"],
            "io_mappings_count": completion_analysis["io_mappings_count"],
            "has_mandatory_outputs": completion_analysis["has_mandatory_outputs"],
            "estimated_time_to_completion": estimated_time,
            "last_updated": meta.get("last_updated"),
            "created_at": meta.get("created_at"),
            "next_action": next_action,
            "message": message,
            "available_actions": available_actions,
            "can_resume": True,
            "resume_instructions": f"To continue, simply say 'Continue with {rule_name}' or mention the specific action needed."
        }
        
        return {
            "success": True,
            "status_info": status_info,
            "rule_structure_summary": {
                "has_tasks": completion_analysis["has_tasks"],
                "has_inputs": completion_analysis["has_inputs"],
                "has_outputs": completion_analysis["has_mandatory_outputs"],
                "has_io_mapping": completion_analysis["has_io_mapping"],
                "total_components": sum([
                    completion_analysis["has_tasks"],
                    completion_analysis["has_inputs"],
                    completion_analysis["has_mandatory_outputs"],
                    completion_analysis["has_io_mapping"]
                ]),
                "completion_percentage": progress_percentage,
                "components_missing": len(missing_components),
                "components_complete": 4 - len(missing_components)  # tasks, inputs, outputs, io_mapping
            },
            "auto_inference_details": {
                "status_source": "analyzed_rule_content",
                "progress_source": "calculated_from_components",
                "phase_source": "inferred_from_structure",
                "reliable": True,
                "analysis_timestamp": datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        return {"success": False, "error": f"Failed to check rule status: {e}"}   

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


if constants.ENABLE_RULE_CREATION_TASK_CHAIN_PROCESS:
    @mcp.tool()
    def fetch_rules_suggestions(user_requirement: str, summary_string: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Tool-based version of `fetch_rules_and_tasks_suggestions` for improved compatibility and prevention of duplicate rule creation.

        This tool serves as the initial step in the rule creation process. It helps determine whether the user's proposed use case matches any existing rule in the catalog.

        PURPOSE:
        - To analyze the user's use case and avoid duplicate rule creation by identifying the most suitable existing rule based on its name, description, and purpose.
        - **NEW: Check for partially developed rules in local system before allowing new rule creation**
        - **NEW: Present resumption options if incomplete rules are found to prevent duplicate work**

        WHEN TO USE:
        - As the first step before initiating a new rule creation process.
        - When the user wants to check if similar rules already exist by leveraging the Rules Suggestions API, instead of browsing the entire catalog manually.
        - When verifying if a suggested rule can be reused or adapted rather than creating one from scratch.
        - When checking for incomplete local rules that should be resumed instead of creating new ones.

        🚫 DO NOT USE THIS TOOL FOR:
        - Checking what rules are available in the ComplianceCow system.
        - This tool only works with the **rule catalog** (not the entire ComplianceCow system).
        - The catalog contains only rules that are published and available for reuse in the catalog.
        - For direct ComplianceCow system lookups, use dedicated system tools instead:
        - `fetch_cc_rule_by_name`
        - `fetch_cc_rule_by_id`
        
        MANDATORY STEP: CONTEXT SUMMARY
        - Before calling the rule catalog API, always rewrite the user’s raw requirement into a single-paragraph
        descriptive summary string (not bullet points, not verbatim input).
        - The summary must capture the essence of the requirement in clear, natural language.
        - This summary string is what will be passed to `fetch_rules_and_tasks_suggestions`.
        - Example:
            User input: "Use GitHub GraphQL API to fetch merged PRs and check if approvals >= 2"
            Summary: "The proposed rule validates compliance for GitHub Pull Requests by retrieving all merged PRs
            through the GitHub GraphQL API, checking whether the number of approvers meets a required threshold,
            and marking them as compliant or non-compliant."

        WHAT IT DOES:
        - Generates a concise summary string from the user's intent or requirements.
        - Calls the Rules Suggestions API with this summary string to retrieve a narrowed list of relevant rules.
        - Performs intelligent matching using metadata (name, description, purpose) from the suggested rules against the user-provided use case details.
        - Uses semantic pattern recognition to identify similar or related rules, even across different systems (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions).
        - Analyzes the `readmeData` field from the `fetch_rule()` response to validate the rule's suitability for the user's use case.
        
        IF A MATCHING RULE IS FOUND:

        - Retrieves complete details via `fetch_rule()`.
        - If the readmeData field is available in the fetch_rule() response, Performs README-based validation using the `readmeData` field from the `fetch_rule()` response to assess its suitability for the user’s use case.
        - If suitable:
        - Returns the rule with full metadata, explanation, and the analysis report.
        - If not suitable:
        - Informs the user that the rule's README content does not align with the intended use case.
        - Prompts the user with clear next-step options:
            - "The rule's README content does not align with your use case. Please choose one of the following options:"
            - Customize the existing rule
                * When the user chooses “Customize the existing rule”, the system must automatically execute the existing rule before allowing any modifications.
                * This execution must happen immediately and without any user confirmation to load the current results and ensure that all changes—such as adding new tasks, altering task sequence, or updating input values—are applied on top of the most recent rule output.
            - Evaluate alternative matching rules
            - Proceed with new rule creation
        - Waits for the user's choice before proceeding.
        
        IF A SIMILAR RULE EXISTS FOR AN ALTERNATE TECHNOLOGY STACK:

        - Detects rules with the same logic but built for a different platform or system (e.g., AzureUserUnusedPermission for SalesforceUserUnusedPermissions)
        - If the readmeData field is available in the fetch_rule() response, Retrieves and analyzes the `readmeData` from the `fetch_rule()` response to compare the implementation details against the user's proposed use case
        - Based on the comparison:
            - If the README content matches or is mostly reusable, suggest using the existing rule structure and logic as a foundation to create a new rule tailored to the user's target system
            - If the README content does not match or is not suitable, clearly inform the user and recommend either modifying the logic significantly or proceeding with a completely new rule from scratch

        IF NO SUITABLE RULE IS FOUND:
        - Clearly informs the user that no relevant rule matches the proposed use case
        - Suggests continuing with new rule creation
        - Optionally highlights similar rules that can be used as a reference

        MANDATORY STEPS:
        README VALIDATION:
        - Always retrieve and analyze `readmeData` from `fetch_rule()`.
        - Ensure the rule's logic, behavior, and intended use align with the user's proposed use case.

        README ANALYSIS REPORT:
        - Generate a clear and concise report for each `readmeData` analysis that classifies the result as a full match, partially reusable, or not aligned.
        - Present this report to the user for review.

        USER CONFIRMATION BEFORE PROCEEDING:
        When analyzing a README file:
        - If no relevant rule matches the proposed use case, or if the README is deemed unsuitable, the tool must pause and request explicit user confirmation before proceeding further.
        - The tool should:
        - Clearly inform the user that no matching rule was found or the README is not appropriate.
        - Suggest creating a new rule as the next step.
        - Optionally recommend similar existing rules that can serve as references to help the user craft the new rule.

        ITERATE UNTIL MATCH:
        - Repeat the above steps until a suitable rule is found or all options are exhausted.

        CROSS-PLATFORM RULE HANDLING:
        - For rules from a different stack:
        - If reusable: suggest customization
        - If not reusable: recommend new rule creation

        Returns:
        - A single rule object with full metadata and verified README match — if an exact match is found
        - A similar rule suggestion with customization options — if a cross-system match is found (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)
        - A message indicating no suitable rule found — with next steps and guidance to create a new rule
        """

        try:
            rule_response = rule.fetch_rules_and_tasks_suggestions(query=summary_string, identifierType="rules", ctx=ctx)
            if not rule_response:
                return {"error": f"No rule found that matches the specified requirements."}
            return rule_response
        except Exception as e:
            return {
                "error": f"An error occurred while retrieving the rule with the specified details: {e}"
            }
            
    # Alternative tool version for task details
    @mcp.tool()
    def get_task_details(task_name: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Tool-based version of get_task_details for improved compatibility.

        DETAILED TASK ANALYSIS REQUIREMENTS:
        - Use this tool if the tasks://details/{task_name} resource is not accessible
        - Extract complete input/output specifications with template information
        - Review detailed capabilities and requirements from the full README
        - Identify template-based inputs (those with the templateFile property)
        - Analyze appTags to determine the application type
        - Review all metadata and configuration options
        - Use this information for accurate task matching and rule structure creation
        
        ============================================================================
        INPUT–OUTPUT STRUCTURE RESOLUTION (NEW – REQUIRED BEHAVIOR)
        ============================================================================
        - **Before creating rule these steps must be done.**
        - After identifying the required inputs for the task:
            1. Check whether any input corresponds to, or depends on,
            the output structure of an existing task in the rule.
            2. If such a relationship exists:
                - The assistant MUST explain clearly why execution is needed
                ("The input <X> depends on the actual output structure of Task <Y>...")
                - Automatically execute ONLY the minimal tasks needed to obtain
                the real output structure.
                - These executions MUST use the execute_task() tool with real data.
            3. Use the real output structure (not a placeholder, not a template)
            to:
                - Construct the correct input schema for the new task
                - Ensure mapping accuracy and avoid invalid input formats
            4. If execution fails:
                - Explain why execution failed
                - Ask the user to provide manual sample data
                - Use the provided sample data for structure inference

        INTENTION-BASED OUTPUT CHAINING:
        - ANALYZE output purpose: Is this meant for direct user consumption or further processing?
        - ASSESS completion level: Does this output fulfill the user's end goal or serve as a stepping stone?
        - EVALUATE consolidation needs: Are multiple outputs meant to be combined for complete picture?
        - DETERMINE transformation requirements: Does raw output need formatting for usability?

        WORKFLOW GAP DETECTION:
        - IDENTIFY outputs that represent partial solutions to user problems
        - DETECT outputs that split information requiring reunification
        - RECOGNIZE outputs that extract data without presenting insights
        - FLAG outputs that validate without providing actionable summaries

        COMPLETION INTENTION MATCHING:
        - SUGGEST tasks that transform intermediate outputs into final deliverables
        - RECOMMEND tasks that consolidate split information into unified reports
        - PROPOSE tasks that add analysis layer to raw validation results
        - ENSURE suggested tasks align with user's stated end goals

        IMPORTANT (MANDATORY BEHAVIOR):
        If the requested task is not found with the user's specification, the system MUST:
        1. Prompt the user to choose how to proceed including the below option.
        - Option: Create task development Ticket.
        2. Wait for the user's response before taking any further action.
        3. If the user chooses to create a task development ticket, call `create_support_ticket()` via the MCP tool, collecting the required input details from the user before submitting.

        Args:
        task_name: The name of the task for which to retrieve details

        Returns:
            A dictionary containing the complete task information if found,
            OR executes the user-selected alternative approach,
            OR creates a support ticket (with collected details) if chosen
        """

        try:
            task = None
            tasks_resp = rule.fetch_task_api(params={
                "name": task_name}, ctx=ctx)

            if rule.is_valid_key(tasks_resp, "items", array_check=True):
                task = TaskVO.from_dict(tasks_resp["items"][0])
            if not task:
                return {"error": f"Task '{task_name}' not found"}
            # Return same detailed information as resource
            readme_content = rule.decode_content(task.readmeData)
            return {"name": task.name, "description": task.description, "tags": task.tags, "appTags": task.appTags, "readme_content": readme_content, "inputs": [{"name": inp.name, "description": inp.description, "dataType": inp.dataType, "required": inp.required, "has_template": bool(inp.templateFile), "format": inp.format if inp.templateFile else None} for inp in task.inputs], "outputs": [{"name": out.name, "description": out.description, "dataType": out.dataType} for out in task.outputs], "template_count": len([inp for inp in task.inputs if inp.templateFile]), "message": f"Use get_template_guidance('{task.name}', '<input_name>') for template details"}
        except Exception as e:
            return {"error": f"An error occurred while fetching the task {task_name} details: {e}"}
    
    @mcp.tool()
    def fetch_rule(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Fetch rule details by rule name.
        
        If the user's request indicates modifying, updating, editing, customizing, adding, or removing rule elements (tasks, inputs, outputs, or sequence), the tool must NOT immediately execute the rule.

        Instead, follow this process:

        1. Identify exactly which inputs, tasks, or configurations the user wants to modify.
        2. Determine whether the requested modification affects any downstream tasks, dependent inputs, or output mappings.
        - If the modification affects other tasks, dependencies, or the rule's final output:
            a. Explain to the user WHY execution is required (e.g., “The input you are changing affects Task X and Task Y, so the rule must be re-executed to generate updated dependent outputs.”).
            b. Before execution, collect all mandatory parameters needed by execute_rule() — do not assume defaults.
            c. Execute the rule.
            d. Call fetch_execution_progress() and display outputs in this format:
                    - TaskName: [task_name]
                    - Files: [list of files]
            e. Ask: “View file contents? (yes/no)”
                - If yes, fetch_output_file() for each selected file and display contents.
        - If the modification does NOT affect dependent tasks:
            - Return the rule metadata and allow the user to modify without executing.

        If the user's request is only to view, inspect, read, or fetch the rule, do NOT execute and simply return the rule metadata.

        All decisions must be based strictly on the user’s request text.

        Args:
            rule_name: Name of the rule to retrieve
                
        Returns:
            Dict containing complete rule structure and metadata
        """
        
        try:
            headers = wsutils.create_header(ctx)
            
            get_rule_resp = wsutils.get(
                path=wsutils.build_api_url(endpoint=f"{constants.URL_FETCH_RULES}?name={rule_name}"),
                header=headers
            )
            
            if rule.is_valid_array(get_rule_resp, "items"):
                rule_structure = get_rule_resp["items"][0]
                if rule.is_valid_array(rule_structure["spec"],"ioMap"):
                    # INFO : From the backend we're setting default values in the ioMap if the values are missing. For MCP flow, we're nullyfying this flow since we have validation for this. 
                    if {'t1.Input.BucketName:=*.Input.BucketName', '*.Output.CompliancePCT_:=t1.Output.CompliancePCT_', '*.Output.ComplianceStatus_:=t1.Output.ComplianceStatus_', '*.Output.LogFile:=t1.Output.LogFile'}==set(rule_structure["spec"]["ioMap"]):
                        rule_structure["spec"]["ioMap"]=[]

                if rule.is_valid_key(rule_structure,"apiVersion") and rule_structure["apiVersion"]=="v1alpha1":
                    rule_structure['apiVersion']="rule.policycow.live/v1alpha1"


                return {
                    "success": True,
                    "rule_name": rule_name,
                    "rule_structure": rule_structure,  # Complete rule as dictionary
                    "message": f"Rule '{rule_name}' retrieved successfully"
                }
            
            else:
                return {
                    "success": False,
                    "error": f"Rule '{rule_name}' not found",
                    "rule_name": rule_name
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to fetch rule '{rule_name}': {e}",
                "rule_name": rule_name
            }

    @mcp.tool()
    def get_rules_summary(ctx: Context | None = None) -> list[dict[str, Any]]:
        """
        Tool-based version of `get_rules_summary` for improved compatibility and prevention of duplicate rule creation.

        This tool serves as the initial step in the rule creation process. It helps determine whether the user's proposed use case matches any existing rule in the catalog.

        PURPOSE:
        - To analyze the user's use case and avoid duplicate rule creation by identifying the most suitable existing rule based on its name, description, and purpose.
        - **NEW: Check for partially developed rules in local system before allowing new rule creation**
        - **NEW: Present resumption options if incomplete rules are found to prevent duplicate work**

        WHEN TO USE:
        - As the first step before initiating a new rule creation process
        - When the user wants to retrieve and review all available rules in the **catalog**
        - When verifying if a similar rule already exists that can be reused or customized
        - **NEW: When checking for incomplete local rules that should be resumed instead of creating new ones**

        🚫 DO NOT USE THIS TOOL FOR:
        - Checking what rules are available in the ComplianceCow system.
        - This tool only works with the **rule catalog** (not the entire ComplianceCow system).
        - The catalog contains only rules that are published and available for reuse in the catalog.
        - For direct ComplianceCow system lookups, use dedicated system tools instead:
        - `fetch_cc_rule_by_name`
        - `fetch_cc_rule_by_id`

        WHAT IT DOES:
        - Retrieves the full list of rules from the catalog with simplified metadata (name, purpose, description)
        - Performs intelligent matching using metadata (name, description, purpose) with user-provided use case details
        - Uses semantic pattern recognition to find similar rules, even across different systems (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)

        IF A MATCHING RULE IS FOUND:

        - Retrieves complete details via `fetch_rule()`.
        - If the readmeData field is available in the fetch_rule() response, Performs README-based validation using the `readmeData` field from the `fetch_rule()` response to assess its suitability for the user’s use case.
        - If suitable:
        - Returns the rule with full metadata, explanation, and the analysis report.
        - If not suitable:
        - Informs the user that the rule's README content does not align with the intended use case.
        - Prompts the user with clear next-step options:
            - "The rule's README content does not align with your use case. Please choose one of the following options:"
            - Customize the existing rule
                * When the user chooses “Customize the existing rule”, the system must automatically execute the existing rule before allowing any modifications.
                * This execution must happen immediately and without any user confirmation to load the current results and ensure that all changes—such as adding new tasks, altering task sequence, or updating input values—are applied on top of the most recent rule output.
            - Evaluate alternative matching rules
            - Proceed with new rule creation
        - Waits for the user's choice before proceeding.
        
        IF A SIMILAR RULE EXISTS FOR AN ALTERNATE TECHNOLOGY STACK:

        - Detects rules with the same logic but built for a different platform or system (e.g., AzureUserUnusedPermission for SalesforceUserUnusedPermissions)
        - If the readmeData field is available in the fetch_rule() response, Retrieves and analyzes the `readmeData` from the `fetch_rule()` response to compare the implementation details against the user's proposed use case
        - Based on the comparison:
            - If the README content matches or is mostly reusable, suggest using the existing rule structure and logic as a foundation to create a new rule tailored to the user's target system
            - If the README content does not match or is not suitable, clearly inform the user and recommend either modifying the logic significantly or proceeding with a completely new rule from scratch

        IF NO SUITABLE RULE IS FOUND:
        - Clearly informs the user that no relevant rule matches the proposed use case
        - Suggests continuing with new rule creation
        - Optionally highlights similar rules that can be used as a reference

        MANDATORY STEPS:
        README VALIDATION:
        - Always retrieve and analyze `readmeData` from `fetch_rule()`.
        - Ensure the rule's logic, behavior, and intended use align with the user's proposed use case.

        README ANALYSIS REPORT:
        - Generate a clear and concise report for each `readmeData` analysis that classifies the result as a full match, partially reusable, or not aligned.
        - Present this report to the user for review.

        USER CONFIRMATION BEFORE PROCEEDING:
        When analyzing a README file:
        - If no relevant rule matches the proposed use case, or if the README is deemed unsuitable, the tool must pause and request explicit user confirmation before proceeding further.
        - The tool should:
        - Clearly inform the user that no matching rule was found or the README is not appropriate.
        - Suggest creating a new rule as the next step.
        - Optionally recommend similar existing rules that can serve as references to help the user craft the new rule.

        ITERATE UNTIL MATCH:
        - Repeat the above steps until a suitable rule is found or all options are exhausted.

        CROSS-PLATFORM RULE HANDLING:
        - For rules from a different stack:
        - If reusable: suggest customization
        - If not reusable: recommend new rule creation

        Returns:
        - A single rule object with full metadata and verified README match — if an exact match is found
        - A similar rule suggestion with customization options — if a cross-system match is found (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)
        - A message indicating no suitable rule found — with next steps and guidance to create a new rule
        """

        try:

            rule_response = rule.fetch_rules_api(ctx=ctx)
            
            if not rule_response:
                return {"error": f"No rule found that matches the specified requirements."}

            return rule_response

        except Exception as e:
            return {
                "error": f"An error occurred while retrieving the rule with the specified details: {e}"
            }

else:
    @mcp.tool()
    def fetch_rules_suggestions(user_requirement: str, summary_string: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Tool-based version of `fetch_rules_and_tasks_suggestions` for improved compatibility and prevention of duplicate rule creation.

        This tool serves as the initial step in the rule creation process. It helps determine whether the user's proposed use case matches any existing rule in the catalog.

        PURPOSE:
        - To analyze the user's use case and avoid duplicate rule creation by identifying the most suitable existing rule based on its name, description, and purpose.
        - **NEW: Check for partially developed rules in local system before allowing new rule creation**
        - **NEW: Present resumption options if incomplete rules are found to prevent duplicate work**

        WHEN TO USE:
        - As the first step before initiating a new rule creation process.
        - When the user wants to check if similar rules already exist by leveraging the Rules Suggestions API, instead of browsing the entire catalog manually.
        - When verifying if a suggested rule can be reused or adapted rather than creating one from scratch.
        - When checking for incomplete local rules that should be resumed instead of creating new ones.

        🚫 DO NOT USE THIS TOOL FOR:
        - Checking what rules are available in the ComplianceCow system.
        - This tool only works with the **rule catalog** (not the entire ComplianceCow system).
        - The catalog contains only rules that are published and available for reuse in the catalog.
        - For direct ComplianceCow system lookups, use dedicated system tools instead:
        - `fetch_cc_rule_by_name`
        - `fetch_cc_rule_by_id`
        
        MANDATORY STEP: CONTEXT SUMMARY
        - Before calling the rule catalog API, always rewrite the user’s raw requirement into a single-paragraph
        descriptive summary string (not bullet points, not verbatim input).
        - The summary must capture the essence of the requirement in clear, natural language.
        - This summary string is what will be passed to `fetch_rules_and_tasks_suggestions`.
        - Example:
            User input: "Use GitHub GraphQL API to fetch merged PRs and check if approvals >= 2"
            Summary: "The proposed rule validates compliance for GitHub Pull Requests by retrieving all merged PRs
            through the GitHub GraphQL API, checking whether the number of approvers meets a required threshold,
            and marking them as compliant or non-compliant."

        WHAT IT DOES:
        - Generates a concise summary string from the user's intent or requirements.
        - Calls the Rules Suggestions API with this summary string to retrieve a narrowed list of relevant rules.
        - Performs intelligent matching using metadata (name, description, purpose) from the suggested rules against the user-provided use case details.
        - Uses semantic pattern recognition to identify similar or related rules, even across different systems (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions).
        - Analyzes the `readmeData` field from the `fetch_rule()` response to validate the rule's suitability for the user's use case.
        
        IF A MATCHING RULE IS FOUND:

        - Retrieves complete details via `fetch_rule()`.
        - If the readmeData field is available in the fetch_rule() response, Performs README-based validation using the `readmeData` field from the `fetch_rule()` response to assess its suitability for the user’s use case.
        - If suitable:
        - Returns the rule with full metadata, explanation, and the analysis report.
        - If not suitable:
        - Informs the user that the rule's README content does not align with the intended use case.
        - Prompts the user with clear next-step options:
            - "The rule's README content does not align with your use case. Please choose one of the following options:"
            - Customize the existing rule
            - Evaluate alternative matching rules
            - Proceed with new rule creation
        - Waits for the user's choice before proceeding.
        
        IF A SIMILAR RULE EXISTS FOR AN ALTERNATE TECHNOLOGY STACK:

        - Detects rules with the same logic but built for a different platform or system (e.g., AzureUserUnusedPermission for SalesforceUserUnusedPermissions)
        - If the readmeData field is available in the fetch_rule() response, Retrieves and analyzes the `readmeData` from the `fetch_rule()` response to compare the implementation details against the user's proposed use case
        - Based on the comparison:
            - If the README content matches or is mostly reusable, suggest using the existing rule structure and logic as a foundation to create a new rule tailored to the user's target system
            - If the README content does not match or is not suitable, clearly inform the user and recommend either modifying the logic significantly or proceeding with a completely new rule from scratch

        IF NO SUITABLE RULE IS FOUND:
        - Clearly informs the user that no relevant rule matches the proposed use case
        - Suggests continuing with new rule creation
        - Optionally highlights similar rules that can be used as a reference

        MANDATORY STEPS:
        README VALIDATION:
        - Always retrieve and analyze `readmeData` from `fetch_rule()`.
        - Ensure the rule's logic, behavior, and intended use align with the user's proposed use case.

        README ANALYSIS REPORT:
        - Generate a clear and concise report for each `readmeData` analysis that classifies the result as a full match, partially reusable, or not aligned.
        - Present this report to the user for review.

        USER CONFIRMATION BEFORE PROCEEDING:
        When analyzing a README file:
        - If no relevant rule matches the proposed use case, or if the README is deemed unsuitable, the tool must pause and request explicit user confirmation before proceeding further.
        - The tool should:
        - Clearly inform the user that no matching rule was found or the README is not appropriate.
        - Suggest creating a new rule as the next step.
        - Optionally recommend similar existing rules that can serve as references to help the user craft the new rule.

        ITERATE UNTIL MATCH:
        - Repeat the above steps until a suitable rule is found or all options are exhausted.

        CROSS-PLATFORM RULE HANDLING:
        - For rules from a different stack:
        - If reusable: suggest customization
        - If not reusable: recommend new rule creation

        Returns:
        - A single rule object with full metadata and verified README match — if an exact match is found
        - A similar rule suggestion with customization options — if a cross-system match is found (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)
        - A message indicating no suitable rule found — with next steps and guidance to create a new rule
        """

        try:
            rule_response = rule.fetch_rules_and_tasks_suggestions(query=summary_string, identifierType="rules", ctx=ctx)
            if not rule_response:
                return {"error": f"No rule found that matches the specified requirements."}
            return rule_response
        except Exception as e:
            return {
                "error": f"An error occurred while retrieving the rule with the specified details: {e}"
            }
            
    # Alternative tool version for task details
    @mcp.tool()
    def get_task_details(task_name: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Tool-based version of get_task_details for improved compatibility.

        DETAILED TASK ANALYSIS REQUIREMENTS:
        - Use this tool if the tasks://details/{task_name} resource is not accessible
        - Extract complete input/output specifications with template information
        - Review detailed capabilities and requirements from the full README
        - Identify template-based inputs (those with the templateFile property)
        - Analyze appTags to determine the application type
        - Review all metadata and configuration options
        - Use this information for accurate task matching and rule structure creation

        INTENTION-BASED OUTPUT CHAINING:
        - ANALYZE output purpose: Is this meant for direct user consumption or further processing?
        - ASSESS completion level: Does this output fulfill the user's end goal or serve as a stepping stone?
        - EVALUATE consolidation needs: Are multiple outputs meant to be combined for complete picture?
        - DETERMINE transformation requirements: Does raw output need formatting for usability?

        WORKFLOW GAP DETECTION:
        - IDENTIFY outputs that represent partial solutions to user problems
        - DETECT outputs that split information requiring reunification
        - RECOGNIZE outputs that extract data without presenting insights
        - FLAG outputs that validate without providing actionable summaries

        COMPLETION INTENTION MATCHING:
        - SUGGEST tasks that transform intermediate outputs into final deliverables
        - RECOMMEND tasks that consolidate split information into unified reports
        - PROPOSE tasks that add analysis layer to raw validation results
        - ENSURE suggested tasks align with user's stated end goals

        IMPORTANT (MANDATORY BEHAVIOR):
        If the requested task is not found with the user's specification, the system MUST:
        1. Prompt the user to choose how to proceed including the below option.
        - Option: Create task development Ticket.
        2. Wait for the user's response before taking any further action.
        3. If the user chooses to create a task development ticket, call `create_support_ticket()` via the MCP tool, collecting the required input details from the user before submitting.

        Args:
        task_name: The name of the task for which to retrieve details

        Returns:
            A dictionary containing the complete task information if found,
            OR executes the user-selected alternative approach,
            OR creates a support ticket (with collected details) if chosen
        """

        try:
            task = None
            tasks_resp = rule.fetch_task_api(params={
                "name": task_name}, ctx=ctx)

            if rule.is_valid_key(tasks_resp, "items", array_check=True):
                task = TaskVO.from_dict(tasks_resp["items"][0])
            if not task:
                return {"error": f"Task '{task_name}' not found"}
            # Return same detailed information as resource
            readme_content = rule.decode_content(task.readmeData)
            return {"name": task.name, "description": task.description, "tags": task.tags, "appTags": task.appTags, "readme_content": readme_content, "inputs": [{"name": inp.name, "description": inp.description, "dataType": inp.dataType, "required": inp.required, "has_template": bool(inp.templateFile), "format": inp.format if inp.templateFile else None} for inp in task.inputs], "outputs": [{"name": out.name, "description": out.description, "dataType": out.dataType} for out in task.outputs], "template_count": len([inp for inp in task.inputs if inp.templateFile]), "message": f"Use get_template_guidance('{task.name}', '<input_name>') for template details"}
        except Exception as e:
            return {"error": f"An error occurred while fetching the task {task_name} details: {e}"}
        
    @mcp.tool()
    def fetch_rule(rule_name: str, ctx: Context | None = None) -> dict[str, Any]:
        """
        Fetch rule details by rule name.

        Args:
            rule_name: Name of the rule to retrieve
            
        Returns:
            Dict containing complete rule structure and metadata
        """
        
        try:
            headers = wsutils.create_header(ctx)
            
            get_rule_resp = wsutils.get(
                path=wsutils.build_api_url(endpoint=f"{constants.URL_FETCH_RULES}?name={rule_name}"),
                header=headers
            )
            
            if rule.is_valid_array(get_rule_resp, "items"):
                rule_structure = get_rule_resp["items"][0]
                if rule.is_valid_array(rule_structure["spec"],"ioMap"):
                    # INFO : From the backend we're setting default values in the ioMap if the values are missing. For MCP flow, we're nullyfying this flow since we have validation for this. 
                    if {'t1.Input.BucketName:=*.Input.BucketName', '*.Output.CompliancePCT_:=t1.Output.CompliancePCT_', '*.Output.ComplianceStatus_:=t1.Output.ComplianceStatus_', '*.Output.LogFile:=t1.Output.LogFile'}==set(rule_structure["spec"]["ioMap"]):
                        rule_structure["spec"]["ioMap"]=[]

                if rule.is_valid_key(rule_structure,"apiVersion") and rule_structure["apiVersion"]=="v1alpha1":
                    rule_structure['apiVersion']="rule.policycow.live/v1alpha1"


                return {
                    "success": True,
                    "rule_name": rule_name,
                    "rule_structure": rule_structure,  # Complete rule as dictionary
                    "message": f"Rule '{rule_name}' retrieved successfully"
                }
            
            else:
                return {
                    "success": False,
                    "error": f"Rule '{rule_name}' not found",
                    "rule_name": rule_name
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to fetch rule '{rule_name}': {e}",
                "rule_name": rule_name
            }
            
    @mcp.tool()
    def get_rules_summary(ctx: Context | None = None) -> list[dict[str, Any]]:
        """
        Tool-based version of `get_rules_summary` for improved compatibility and prevention of duplicate rule creation.

        This tool serves as the initial step in the rule creation process. It helps determine whether the user's proposed use case matches any existing rule in the catalog.

        PURPOSE:
        - To analyze the user's use case and avoid duplicate rule creation by identifying the most suitable existing rule based on its name, description, and purpose.
        - **NEW: Check for partially developed rules in local system before allowing new rule creation**
        - **NEW: Present resumption options if incomplete rules are found to prevent duplicate work**

        WHEN TO USE:
        - As the first step before initiating a new rule creation process
        - When the user wants to retrieve and review all available rules in the **catalog**
        - When verifying if a similar rule already exists that can be reused or customized
        - **NEW: When checking for incomplete local rules that should be resumed instead of creating new ones**

        🚫 DO NOT USE THIS TOOL FOR:
        - Checking what rules are available in the ComplianceCow system.
        - This tool only works with the **rule catalog** (not the entire ComplianceCow system).
        - The catalog contains only rules that are published and available for reuse in the catalog.
        - For direct ComplianceCow system lookups, use dedicated system tools instead:
        - `fetch_cc_rule_by_name`
        - `fetch_cc_rule_by_id`

        WHAT IT DOES:
        - Retrieves the full list of rules from the catalog with simplified metadata (name, purpose, description)
        - Performs intelligent matching using metadata (name, description, purpose) with user-provided use case details
        - Uses semantic pattern recognition to find similar rules, even across different systems (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)

        IF A MATCHING RULE IS FOUND:

        - Retrieves complete details via `fetch_rule()`.
        - If the readmeData field is available in the fetch_rule() response, Performs README-based validation using the `readmeData` field from the `fetch_rule()` response to assess its suitability for the user’s use case.
        - If suitable:
        - Returns the rule with full metadata, explanation, and the analysis report.
        - If not suitable:
        - Informs the user that the rule's README content does not align with the intended use case.
        - Prompts the user with clear next-step options:
            - "The rule's README content does not align with your use case. Please choose one of the following options:"
            - Customize the existing rule
            - Evaluate alternative matching rules
            - Proceed with new rule creation
        - Waits for the user's choice before proceeding.
        
        IF A SIMILAR RULE EXISTS FOR AN ALTERNATE TECHNOLOGY STACK:

        - Detects rules with the same logic but built for a different platform or system (e.g., AzureUserUnusedPermission for SalesforceUserUnusedPermissions)
        - If the readmeData field is available in the fetch_rule() response, Retrieves and analyzes the `readmeData` from the `fetch_rule()` response to compare the implementation details against the user's proposed use case
        - Based on the comparison:
            - If the README content matches or is mostly reusable, suggest using the existing rule structure and logic as a foundation to create a new rule tailored to the user's target system
            - If the README content does not match or is not suitable, clearly inform the user and recommend either modifying the logic significantly or proceeding with a completely new rule from scratch

        IF NO SUITABLE RULE IS FOUND:
        - Clearly informs the user that no relevant rule matches the proposed use case
        - Suggests continuing with new rule creation
        - Optionally highlights similar rules that can be used as a reference

        MANDATORY STEPS:
        README VALIDATION:
        - Always retrieve and analyze `readmeData` from `fetch_rule()`.
        - Ensure the rule's logic, behavior, and intended use align with the user's proposed use case.

        README ANALYSIS REPORT:
        - Generate a clear and concise report for each `readmeData` analysis that classifies the result as a full match, partially reusable, or not aligned.
        - Present this report to the user for review.

        USER CONFIRMATION BEFORE PROCEEDING:
        When analyzing a README file:
        - If no relevant rule matches the proposed use case, or if the README is deemed unsuitable, the tool must pause and request explicit user confirmation before proceeding further.
        - The tool should:
        - Clearly inform the user that no matching rule was found or the README is not appropriate.
        - Suggest creating a new rule as the next step.
        - Optionally recommend similar existing rules that can serve as references to help the user craft the new rule.

        ITERATE UNTIL MATCH:
        - Repeat the above steps until a suitable rule is found or all options are exhausted.

        CROSS-PLATFORM RULE HANDLING:
        - For rules from a different stack:
        - If reusable: suggest customization
        - If not reusable: recommend new rule creation

        Returns:
        - A single rule object with full metadata and verified README match — if an exact match is found
        - A similar rule suggestion with customization options — if a cross-system match is found (e.g., AzureUserUnusedPermission vs SalesforceUserUnusedPermissions)
        - A message indicating no suitable rule found — with next steps and guidance to create a new rule
        """

        try:

            rule_response = rule.fetch_rules_api(ctx=ctx)
            
            if not rule_response:
                return {"error": f"No rule found that matches the specified requirements."}

            return rule_response

        except Exception as e:
            return {
                "error": f"An error occurred while retrieving the rule with the specified details: {e}"
            }
            