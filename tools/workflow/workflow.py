import json
import traceback
import base64
import asyncio
from typing import List
from typing import Tuple
import base64


from utils import utils
from utils.debug import logger
from mcpconfig.config import mcp

from constants import constants
from mcptypes import workflow_tools_type as vo
import yaml
from fastmcp import Context

import constants.error_constants as error_constants

@mcp.tool()
async def create_workflow(workflow_yaml: str, ctx: Context | None = None) -> str:
    """
    Create a new workflow using YAML definition. Always display the workflow diagram. 
    Before creation confirm workflow name and creation with the user before executing this tool. 
    Later use 'modify_workflow' tool to update states, activities, conditions, and transitions.

    yaml struct:
    
    metadata:
        name:
        description:
        summary:
        mermaidDiagram:

    This function creates a workflow from a YAML specification.

    Create workflow (establishes the ID)
    Update summary (document what we're building)
    Update mermaid diagram (visualize the flow)
    Then modify workflow (implement the actual logic)
    
    Args:
        workflow_yaml: YAML string defining the workflow structure
        
    Returns:
        Success message with workflow ID or error message
    """
    try:
        logger.info("Creating workflow from YAML")
        logger.debug(f"Workflow YAML: {workflow_yaml}")

        workflow_name = ""
        workflow_description = ""
        try:
            parsed_yaml = yaml.safe_load(workflow_yaml) if isinstance(workflow_yaml, str) else workflow_yaml
            if isinstance(parsed_yaml, dict):
                metadata = parsed_yaml.get("metadata")
                if not isinstance(metadata, dict):
                    metadata = {}
                    parsed_yaml["metadata"] = metadata
                metadata["tags"] = {"Channel": ["MCP_HOST"]}
                workflow_name = metadata.get("name") or ""
                workflow_description = metadata.get("description") or ""
                workflow_yaml = yaml.safe_dump(parsed_yaml, sort_keys=False)
        except Exception:
            logger.warning("Failed to set MCP tags or extract metadata from workflow YAML; proceeding with defaults")

        # Create workflow configuration first
        output = await utils.make_API_call_to_CCow_and_get_response(constants.URL_WORKFLOW_CREATE,"POST",workflow_yaml,type="yaml", ctx=ctx)
        logger.debug("create workflow output: {}\n".format(output))

        if not (output and isinstance(output, dict) and output.get("status") and output["status"].get("id")):
            logger.error(f"Failed to create workflow: {output}")
            return f"Failed to create workflow: {output}"

        workflow_id = output["status"]["id"]

        logger.info(f"Workflow created successfully with ID: {workflow_id}")

        # Build UI URL
        try:
            base_host = constants.host.rstrip("/api") if hasattr(constants, "host") and isinstance(constants.host, str) else getattr(constants, "host", "")
            ui_url = f"{base_host}/ui/workflow-config/{workflow_id}" if base_host else ""
        except Exception:
            ui_url = ""

        logger.info(f"Workflow created URL : {ui_url}")
        
        # Create Workflow Specification 
        spec_payload = {
            "metadata": {
                "name": workflow_name,
                "description": workflow_description,
                "tags":{
                    "Channel":["MCP_HOST"]
                }
            },
            "spec": {
                "resources": [
                    {
                        "type": "GENERIC",
                        "includes": [],
                        "excludes": [],
                    }
                ],
                "reviewers": {"references": []},
                "approvers": {"references": []},
            },
        }

        spec_resp = await utils.make_API_call_to_CCow_and_get_response(constants.URL_WORKFLOW_SPECS, "POST", spec_payload, ctx=ctx)
        logger.debug("create workflow spec output: {}\n".format(spec_resp))

        spec_id = None
        if isinstance(spec_resp, dict) and spec_resp.get("status") and spec_resp["status"].get("id"):
            spec_id = spec_resp["status"]["id"]
            logger.info(f"Workflow spec created successfully with ID: {spec_id}")
        else:
            logger.error(f"Failed to create workflow spec: {spec_resp}")

        # If spec creation failed, return summary without attempting binding
        if not spec_id:
            msg = f"Workflow created (ID: {workflow_id})."
            if ui_url:
                msg += f" UI: {ui_url}"
            return msg

        # Create Workflow Binding using the same name/description
        binding_payload = {
            "metadata": {
                "name": workflow_name,
                "description": workflow_description,
                "tags":{
                    "Channel":["MCP_HOST"]
                }
            },
            "spec": {
                "workflowResourceSpec": workflow_name,
                "workflowConfiguration": "",
                "workflowAdvancedConfig": workflow_name,
                "reviewers": {"references": []},
                "approvers": {"references": []},
            },
        }

        binding_resp = await utils.make_API_call_to_CCow_and_get_response(constants.URL_WORKFLOW_BINDINGS, "POST", binding_payload, ctx=ctx)
        logger.debug("create workflow binding output: {}\n".format(binding_resp))

        binding_id = None
        if isinstance(binding_resp, dict) and binding_resp.get("status") and binding_resp["status"].get("id"):
            binding_id = binding_resp["status"]["id"]
            logger.info(f"Workflow binding created successfully with ID: {binding_id}")
        else:
            logger.error(f"Failed to create workflow binding: {binding_resp}")

        # Build final message summarizing all creations
        if not binding_id:
            msg = f"Workflow created (ID: {workflow_id})."
            if ui_url:
                msg += f" UI: {ui_url}"
            return msg

        msg = f"Workflow created (ID: {workflow_id})."
        if ui_url:
            msg += f" UI: {ui_url}"
        return msg

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("create_workflow: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def update_workflow_summary(id:str,summary:str, ctx: Context | None = None) -> dict | str:
    """
        Args:
            - id (str): workflow id. This can be fetched from path /status/id of 'get_workflows' output
            - summary (str): workflow summary, preferably ReadMe.
    """
    try:
        logger.info(f"update_workflow_summary: {id}, {summary}\n")

        req=[
            {
                "op":"add",
                "path": "/metadata/summary",
                "value": summary
            }
        ]
        output=await utils.make_API_call_to_CCow_and_get_response("/v3/workflow-configs/"+id,"PATCH",req, ctx=ctx)
        logger.debug("update_workflow_summary output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("update_workflow_summary error: {}\n".format(output))
            return "Facing internal error"
        return output
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("update_workflow_summary: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def update_workflow_mermaid_diagram(id:str,mermaidDiagram:str, ctx: Context | None = None) -> dict | str:
    """
        Args:
            - id (str): workflow id. This can be fetched from path /status/id of 'get_workflows' output
            - mermaidDiagram (str): workflow mermaid diagram
    """
    try:
        logger.info(f"update_workflow_mermaid_diagram: {id}, {mermaidDiagram}\n")

        req=[
            {
                "op":"add",
                "path": "/metadata/mermaidDiagram",
                "value": mermaidDiagram
            }
        ]
        output=await utils.make_API_call_to_CCow_and_get_response("/v3/workflow-configs/"+id,"PATCH",req, ctx=ctx)
        logger.debug("update_workflow_mermaid_diagram output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("update_workflow_mermaid_diagram error: {}\n".format(output))
            return "Facing internal error"
        return output
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("update_workflow_mermaid_diagram: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def modify_workflow(workflow_yaml: str, workflow_id: str, ctx: Context | None = None) -> str:
    """
    Modify an existing workflow using YAML definition.
    
    The workflow ID (UUID) is required to identify which workflow to modify. This 
    function updates an existing workflow with a new YAML specification. The YAML 
    should define the workflow structure including states, activities, conditions, 
    and transitions. Always display the workflow diagram and confirm with the 
    user before executing this tool.

    BEFORE using 'modify_workflow' tool, you MUST check:
    - Do I have the complete CCow workflow YAML schema?
    - Do I know the exact state configuration requirements?
    - Do I understand the data flow and variable reference patterns?
    If the answer to ANY of these is "no", respond with:
    "I need CCow workflow schema knowledge to properly implement this workflow. 
    Please provide the workflow YAML specification, state definitions, and 
    integration patterns before I proceed with modify_workflow."

    
    Args:
        workflow_yaml: YAML string defining the updated workflow structure
        workflow_id: ID of the workflow to modify
        
    Returns:
        Success message or error message
    """
    try:
        logger.info(f"Modifying workflow with ID: {workflow_id}")
        logger.debug(f"Updated workflow YAML: {workflow_yaml}")

        response =await utils.make_API_call_to_CCow_and_get_response(f"{constants.URL_WORKFLOW_CREATE}/{workflow_id}","PUT",workflow_yaml,type="yaml",return_raw=True, ctx=ctx)
        logger.debug("create workflow output: {}\n".format(response))

        if response.status_code == 502:
            return error_constants.ERROR_BAD_GATEWAY

        if response.status_code == 204:
            logger.info("Workflow updated successfully")
            return "Workflow updated successfully"
        else:
            try:
                error_msg = response.json().get("ErrorMessage", response.text)
            except Exception:
                error_msg = response.text or f"HTTP {response.status_code}"
            logger.error(f"Failed to modify workflow: {error_msg}")
            return f"Failed to update workflow: {error_msg}"
    
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("modify_workflow: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def create_workflow_custom_event(
    displayable: str,
    desc: str,
    payload: list[vo.WorkflowCustomEventPayloadVO],
    categoryId: str = "7",
    eventType: str = "CUSTOM_EVENT",
    confirm: bool = False,
    ctx: Context | None = None
) -> str:
    """
    Create a Workflow Catalog Custom Event.
    Show a preview of the event configuration and ask for user confirmation before proceeding.
    Only create the event after explicit confirmation from user (confirm=True)
    This tool validates payload item types against allowed values and requires explicit
    user confirmation before creating the event.

    Args:
        - displayable: Event display name
        - desc: Event description
        - categoryId: Event category identifier
        - payload: List of payload items. Each item must have {name, type, desc}
                   and type must be one of: Text, MultilineText, TextArray, DynamicTextArray,
                   Number, File, Boolean, Json
        - eventType: Event type. Default: "CUSTOM_EVENT"
        - confirm: Boolean flag. If False, will show a preview for user confirmation.
                  Only returns True after user explicitly accepts the preview.
    Returns:
        - Success or error message
    """
    try:
        logger.info("create_workflow_custom_event: validating inputs")

        sanitized_payload: list[dict] = []
        for idx, item in enumerate(payload):
            if not isinstance(item, vo.WorkflowCustomEventPayloadVO):
                try:
                    item = vo.WorkflowCustomEventPayloadVO.model_validate(item)
                except Exception:
                    return f"Invalid payload item at index {idx}."

            sanitized_payload.append(item.model_dump())

        body_model = vo.WorkflowCustomEventCreateVO(
            displayable=displayable,
            desc=desc,
            categoryId=str(categoryId),
            payload=[vo.WorkflowCustomEventPayloadVO(**item) for item in sanitized_payload],
            type=eventType or "CUSTOM_EVENT",
        )
        body = body_model.model_dump()

        if not confirm:
            return json.dumps(
                {
                    "message": "Confirmation required before creating event",
                    "preview": body,
                    "next_step": "Re-run with confirm=True to create",
                },
                indent=2,
            )

        logger.info("create_workflow_custom_event: submitting request to API")
        output = await utils.make_API_call_to_CCow_and_get_response(
            constants.URL_WORKFLOW_EVENTS,
            "POST",
            body,
            ctx=ctx,
        )
        logger.debug("create_workflow_custom_event output: {}\n".format(output))

        if isinstance(output, str) or (isinstance(output, dict) and "id" not in output):
            logger.error(f"create_workflow_custom_event error: {output}")
            return f"Failed to create event: {output}"

        created_id = output.get("id")

        if created_id:
            return json.dumps({"id": created_id})

        return "Failed to create event"

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("create_workflow_custom_event: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def trigger_workflow(
    workflowConfigId: str,
    event: str,
    inputs: dict | None = None,
    confirm: bool = False,
    ctx: Context | None = None
) -> str:
    """
    Trigger a workflow by the given workflow config id.
    
    Args:
        - workflowConfigId: The workflow config id 
        - event: Start event name.
        - inputs: Additional input payload for the event. IMPORTANT: Input values must be obtained from the user only - do not pass random/placeholder values. Each field requires meaningful user-provided values.
        - confirm: If False, shows a preview of required inputs and does not execute. If True, executes.

    Returns:
        - JSON string containing execution acknowledgement or error message
    """
    try:
        logger.info(f"trigger_workflow: workflowConfigId={workflowConfigId}, event={event}, inputs={inputs}, confirm={confirm}")

        query = {
            "workflow_advanced_config_id": workflowConfigId,
            "page": 1,
            "page_size": 1,
        }
        bindings_resp = await utils.make_API_call_to_CCow_and_get_response(
            f"{constants.URL_WORKFLOW_BINDINGS}", "GET", query, ctx=ctx
        )
        logger.debug(f"trigger_workflow bindings_resp: {bindings_resp}")

        if isinstance(bindings_resp, str) or not isinstance(bindings_resp, dict) or not bindings_resp.get("items"):
            logger.error(f"Failed to resolve workflow binding: {bindings_resp}")
            return "Failed to execute workflow"

        item = bindings_resp["items"][0]
        status = item.get("status", {}) if isinstance(item, dict) else {}
        binding_id = status.get("id", "")

        if not binding_id:
            logger.error("No binding ID found in response")
            return "Failed to execute workflow"

        exec_inputs = inputs.copy() if isinstance(inputs, dict) else {}
        if event and isinstance(event, str):
            exec_inputs["event"] = event
        if "event" not in exec_inputs or not isinstance(exec_inputs["event"], str) or not exec_inputs["event"].strip():
            logger.error("Missing or invalid event in inputs")
            return "Starting event is required"

        required_fields: list[str] = []
        try:
            logger.info("Fetching workflow events to validate required fields")
            events_resp = await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_EVENTS, ctx)

            if isinstance(events_resp, dict) and events_resp.get("items"):
                for ev in events_resp["items"]:
                    displayable = ev.get("displayable")
                    if isinstance(displayable, str) and displayable.strip() == exec_inputs["event"].strip():
                        payload_list = ev.get("payload") or []
                        for p in payload_list:
                            name = p.get("name") if isinstance(p, dict) else None
                            if isinstance(name, str) and name:
                                required_fields.append(name)
                        break
            logger.debug(f"Required fields for event: {required_fields}")
        except Exception as e:
            logger.error(f"Error fetching workflow events: {e}")
            required_fields = required_fields

        missing = []
        if required_fields:
            for f in required_fields:
                if f not in exec_inputs or exec_inputs.get(f) in [None, ""]:
                    missing.append(f)
            logger.debug(f"Missing required fields: {missing}")

        preview_body = {
            "workflowBindingId": binding_id,
            "input": exec_inputs,
        }

        if not confirm or missing:
            logger.info("Returning preview/validation response")
            return json.dumps({
                "message": "Confirmation required before executing workflow",
                "event": exec_inputs.get("event"),
                "requiredInputs": required_fields,
                "provided": {k: v for k, v in exec_inputs.items() if k != "event"},
                "missing": missing,
                "next_step": "Provide missing inputs (if any) and re-run with confirm=True to execute"
            })

        body = {
            "workflowBindingId": binding_id,
            "input": exec_inputs,
        }

        logger.info(f"Executing workflow: {json.dumps(body)}")


        exec_resp = await utils.make_API_call_to_CCow_and_get_response(
            constants.URL_WORKFLOW_BINDINGS_EXECUTE, "POST", body, ctx=ctx
        )
        logger.debug(f"trigger_workflow exec_resp: {exec_resp}")

        if isinstance(exec_resp, str):
            logger.error(f"Error response from execute API: {exec_resp}")
            return exec_resp

        logger.info("Workflow triggered successfully")
        return json.dumps(exec_resp)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("trigger_workflow error: {}\n".format(e))
        return "Facing internal error"