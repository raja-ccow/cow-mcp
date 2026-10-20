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
async def list_workflow_event_categories(ctx: Context | None = None) -> vo.WorkflowEventCategoryListVO:
    """
    Retrieve available workflow event categories.
    
    Event categories help organize workflow triggers by type (e.g., assessment events, 
    time-based events, user actions). This is useful for filtering and selecting 
    appropriate events when building workflows.
    
    Returns:
        - eventCategories: List of event categories with type and displayable name
        - error: Error message if retrieval fails
    """
    try:
        logger.info("list_workflow_event_categories: \n")

        output=await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_EVENT_CATEGORIES,ctx)
        logger.debug("workflow event categories output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow event categories error: {}\n".format(output))
            return vo.WorkflowEventCategoryListVO(error="Facing internal error")
        
        eventCategories: list[vo.WorkflowEventCategoryItemVO]=[]
        for item in output["items"]:
            if "type" in item and "displayable" in item:
                eventCategories.append(vo.WorkflowEventCategoryItemVO.model_validate(item))
        
        logger.debug("modified event categories: {}\n".format(vo.WorkflowEventCategoryListVO(eventCategories=eventCategories).model_dump()))

        return vo.WorkflowEventCategoryListVO(eventCategories=eventCategories)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow event categories: {}\n".format(e))
        return vo.WorkflowEventCategoryListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_events(ctx: Context | None = None) -> vo.WorkflowEventListVO:
    """
    Retrieve available workflow events that can trigger workflows.
    
    Events are the starting points of workflows. Each event has a payload that 
    provides data to subsequent workflow nodes. Events are categorized into two types:
    
    **System Events**: Automatically triggered by the system when specific actions occur.
    Examples include:
    - Assessment run completed
    - Form submitted
    - Scheduled time-based triggers
    
    **Custom Events**: Manually triggered events that can be used to:
    - Trigger workflows from within other workflows
    - Integrate with external systems
    - Enable manual workflow execution
    
    Returns:
        - systemEvents (list[WorkflowEventVO]): A list of system events that are automatically triggered.
            - id (str)
            - categoryId (str)
            - desc (str)
            - displayable (str)
            - payload [list[WorkflowPayloadVO]]
            - status (str)
            - type (str)
        - customEvents (list[WorkflowEventVO]): A list of custom events that can be manually triggered.
            - id (str)
            - categoryId (str)
            - desc (str)
            - displayable (str)
            - payload [list[WorkflowPayloadVO]]
            - status (str)
            - type (str)
        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("Fetching workflow events")
        
        output = await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_EVENTS, ctx)
        logger.debug(f"Events response: {output}")
        
        if isinstance(output, str) or "error" in output:
            logger.error(f"Failed to fetch events: {output}")
            return vo.WorkflowEventListVO(error="Failed to retrieve events")
        
        systemEvents: list[vo.WorkflowEventVO] = []
        customEvents: list[vo.WorkflowEventVO] = []
        
        for item in output.get("items", []):
            if "type" in item and "displayable" in item and item.get("status") == "Active":
                event = vo.WorkflowEventVO.model_validate(item)
                
                # Categorize events based on eventType
                if item.get("type") == "CUSTOM_EVENT":
                    customEvents.append(event)
                else:
                    systemEvents.append(event)
        
        logger.debug("modified events - systemEvents: {}, customEvents: {}\n".format(
            len(systemEvents), len(customEvents)))

        return vo.WorkflowEventListVO(systemEvents=systemEvents, customEvents=customEvents)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow events: {}\n".format(e))
        return vo.WorkflowEventListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_activity_types(ctx: Context | None = None) -> list[str]:
    """
    Get available workflow activity types.
    
    Activity types define what kind of actions can be performed in workflow nodes:
    - Pre-build Function: Execute predefined logic
    - Pre-build Rule: Execute a rule
    - Pre-build Task: Trigger a predefined task
    
    Returns:
        List of available activity types
    """
    try:
        return ['Pre-build Function', 'Pre-build Rule', 'Pre-build Task', 'Existing Workflow']
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("list_workflow_activity_types error: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def list_workflow_function_categories(ctx: Context | None = None) -> vo.WorkflowActivityCategoryListVO:
    """
    Retrieve available workflow function categories.
    
    Function categories help organize workflow activities by type. This is useful 
    for filtering and selecting appropriate functions when building workflows.
    
    Returns:
        - activity categories (list[WorkflowActivityCategoryItemVO]): List of activity categories.
            - name (str): Name of the category.
        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("list_workflow_activity_categories: \n")

        output=await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_ACTIVITY_CATEGORIES, ctx)
        logger.debug("workflow activity categories output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow activity categories error: {}\n".format(output))
            return vo.WorkflowActivityCategoryListVO(error="Facing internal error")
        
        activityCategories: list[vo.WorkflowActivityCategoryItemVO]=[]
        for item in output["items"]:
            if "displayable" in item:
                activityCategories.append(vo.WorkflowActivityCategoryItemVO.model_validate(item))
        
        logger.debug("modified activity categories: {}\n".format(vo.WorkflowActivityCategoryListVO(activityCategories=activityCategories).model_dump()))

        return vo.WorkflowActivityCategoryListVO(activityCategories=activityCategories)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow activity categories: {}\n".format(e))
        return vo.WorkflowActivityCategoryListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_functions(ctx: Context | None = None) -> vo.WorkflowActivityListVO:
    """
    Retrieve available workflow functions (activities).
    
    Functions are the core actions that can be performed in workflow nodes. They 
    take inputs and produce outputs that can be used by subsequent nodes. Only 
    active functions are returned.
    
    Returns:
        - activities (list[WorkflowActivityVO]): List of active workflow functions with input/output specifications
            - id: Optional[str] = ""
            - categoryId (str)
            - desc (str)
            - displayable Optional[str] = ""
            - name (str)
            - inputs [list[WorkflowInputsVO]]
            - outputs [list[WorkflowOutputsVO]]
            - status (str)

        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("list_workflow_activities: \n")

        output=await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_ACTIVITIES, ctx)
        logger.debug("workflow activities output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow activities error: {}\n".format(output))
            return vo.WorkflowActivityListVO(error="Facing internal error")
        
        activities: list[vo.WorkflowActivityVO]=[]
        for item in output["items"]:
            if "displayable" in item and item.get("status") == "Active":
                activities.append(vo.WorkflowActivityVO.model_validate(item))
        
        logger.debug("modified activities: {}\n".format(vo.WorkflowActivityListVO(activities=activities).model_dump()))

        return vo.WorkflowActivityListVO(activities=activities)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow activities: {}\n".format(e))
        return vo.WorkflowActivityListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_rules(ctx: Context | None = None) -> vo.WorkflowRuleListVO:
    """
    Retrieve available workflow rules.
    
    Rules are predefined logic that can be executed in workflow nodes. They typically 
    handle data processing, validation, or business logic. Rules have inputs and 
    outputs that can be mapped to other workflow components.
    
    Returns:
        - rules (list[WorkflowRuleVO]): List of available workflow rules with input/output specifications
            - id (str)
            - name: (str)
            - description (str)
            - ruleInputs: [list[WorkflowRuleInputsVO]]
            - ruleOutputs: [list[WorkflowRuleOutputsVO]]

        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("list_workflow_prebuild_rules: \n")

        output=await utils.make_GET_API_call_to_CCow(f"{constants.URL_WORKFLOW_PREBUILD_RULES}?type=rule&meta_tags=MCP", ctx)
        logger.debug("workflow rules output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow rules error: {}\n".format(output))
            return vo.WorkflowRuleListVO(error="Facing internal error")
        
        for item in output.get("items", []):
            if "ruleInputs" in item and isinstance(item["ruleInputs"], dict):
                item["ruleInputs"] = list(item["ruleInputs"].values())

            if "ruleOutputs" in item and isinstance(item["ruleOutputs"], dict):
                outputs = item["ruleOutputs"]
                transformed_rule_outputs = []
                for key, value in outputs.items():
                    if isinstance(value, dict) and not value:
                        transformed_rule_outputs.append({"name": key})
                    else:
                        transformed_rule_outputs.append(value)
                item["ruleOutputs"] = transformed_rule_outputs

        logger.error("Transformed rules output: {}\n".format(output))

        rules: list[vo.WorkflowRuleVO]=[]
        for item in output["items"]:
            if "name" in item:
                rules.append(vo.WorkflowRuleVO.model_validate(item))
        
        logger.debug("modified rules: {}\n".format(vo.WorkflowRuleListVO(rules=rules).model_dump()))

        return vo.WorkflowRuleListVO(rules=rules)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow rules: {}\n".format(e))
        return vo.WorkflowRuleListVO(error="Facing internal error")

@mcp.tool()
async def fetch_workflow_rule(name: str, ctx: Context | None = None) -> vo.WorkflowRuleListVO:
    """
    Retrieve a specific workflow rule by name.
    
    Finds and returns the single workflow rule that matches the provided name. This rule
    contains the input/output specifications needed for workflow operations.
    
    Args:
        name (str): The name of the workflow rule to retrieve
        
    Returns:
        - rules (list[WorkflowRuleVO]): List containing the single matched workflow rule with input/output specifications
            - id: (str)
            - name: (str) 
            - description: (str)
            - ruleInputs: [list[WorkflowRuleInputsVO]]
            - ruleOutputs: [list[WorkflowRuleOutputsVO]]

        - error (Optional[str]): An error message if any issues occurred during retrieval.
    """
    try:
        logger.info(f"fetch_workflow_rule: searching for rule '{name}'\n")

        output = await utils.make_GET_API_call_to_CCow(f"{constants.URL_WORKFLOW_PREBUILD_RULES}?name={name}", ctx)
        logger.debug("workflow rule output: {}\n".format(output))
        
        if isinstance(output, str) or "error" in output:
            logger.error("workflow rule error: {}\n".format(output))
            return vo.WorkflowRuleListVO(error="Facing internal error")
        
        for item in output.get("items", []):
            if "ruleInputs" in item and isinstance(item["ruleInputs"], dict):
                item["ruleInputs"] = list(item["ruleInputs"].values())

            if "ruleOutputs" in item and isinstance(item["ruleOutputs"], dict):
                outputs = item["ruleOutputs"]
                transformed_rule_outputs = []
                for key, value in outputs.items():
                    if isinstance(value, dict) and not value:
                        transformed_rule_outputs.append({"name": key})
                    else:
                        transformed_rule_outputs.append(value)
                item["ruleOutputs"] = transformed_rule_outputs

        if output.get("items") and len(output["items"]) > 0:
            item = output["items"][0]
            rule = vo.WorkflowRuleVO.model_validate(item)
            logger.debug("retrieved workflow rule: {}\n".format(rule.model_dump()))
            return vo.WorkflowRuleListVO(rules=[rule])
        
        logger.warning(f"No workflow rule returned for name: {name}")
        return vo.WorkflowRuleListVO(error=f"No workflow rule returned for name: {name}")

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("fetch_workflow_rule error: {}\n".format(e))
        return vo.WorkflowRuleListVO(error="Facing internal error")

@mcp.tool()
async def fetch_task_readme(name: str, ctx: Context | None = None) -> vo.TaskReadmeResponseVO:
    """
    Retrieve README documentation for a specific task by name.
    
    Fetches the complete README documentation for a task, providing 
    detailed information about the task's purpose, usage instructions, prerequisites, 
    and implementation steps. This is useful for understanding how to properly use 
    a task in workflows.
    
    Args:
        name (str): The exact name of the task to retrieve README for
        
    Returns:
        - readmeText (str): Complete README documentation as readable text
        - taskName (str): Name of the task for reference
        - error (str): Error message if retrieval fails or README not available
    """
    try:
        logger.info(f"fetch_task_readme: searching for task '{name}'\n")

        output = await utils.make_GET_API_call_to_CCow(f"{constants.URL_FETCH_TASK_README}?name={name}", ctx)
        logger.debug("task readme output: {}\n".format(output))
        
        if isinstance(output, str) or "error" in output:
            logger.error("task readme error: {}\n".format(output))
            return vo.TaskReadmeResponseVO(error="Facing internal error")
        
        if not output.get("items") or len(output["items"]) == 0:
            logger.warning(f"No task found with name: {name}")
            return vo.TaskReadmeResponseVO(taskName=name, error=f"Task '{name}' not available")
        
        task_item = output["items"][0]
        task_name = task_item.get("name", name)
        readme_data = task_item.get("readmeData", "")
        
        if not readme_data:
            logger.warning(f"No README data found for task: {name}")
            return vo.TaskReadmeResponseVO(taskName=task_name, error=f"README not available for task: {name}")
        
        try:
            readme_text = base64.b64decode(readme_data).decode('utf-8')
            logger.debug(f"Successfully decoded README for task: {task_name}")
            return vo.TaskReadmeResponseVO(readmeText=readme_text, taskName=task_name)
        except Exception as decode_error:
            logger.error(f"Failed to decode README data for task {name}: {decode_error}")
            return vo.TaskReadmeResponseVO(taskName=task_name, error=f"Failed to decode README data for task: {name}")

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("fetch_task_readme error: {}\n".format(e))
        return vo.TaskReadmeResponseVO(error="Facing internal error")

@mcp.tool()
async def fetch_rule_readme_documentaion(name: str, ctx: Context | None = None) -> vo.RuleReadmeResponseVO:
    """
    Retrieve README documentation for a specific rule by name.
    
    Fetches the complete README documentation for a rule, providing 
    detailed information about the rule's purpose, usage instructions, prerequisites, 
    and implementation steps. This is useful for understanding how to properly use 
    a rule in workflows.
    
    Args:
        name (str): The exact name of the rule to retrieve README for
        
    Returns:
        - readmeText (str): Complete README documentation as readable text
        - ruleName (str): Name of the rule for reference
        - error (str): Error message if retrieval fails or README not available
    """
    try:
        logger.info(f"fetch_rule_readme: searching for rule '{name}'\n")

        output = await utils.make_GET_API_call_to_CCow(f"{constants.URL_FETCH_RULE_README}?name={name}", ctx)
        logger.debug("rule readme output: {}\n".format(output))
        
        if isinstance(output, str) or "error" in output:
            logger.error("rule readme error: {}\n".format(output))
            return vo.RuleReadmeResponseVO(error="Facing internal error")
        
        if not output.get("items") or len(output["items"]) == 0:
            logger.warning(f"No rule found with name: {name}")
            return vo.RuleReadmeResponseVO(ruleName=name, error=f"Rule '{name}' not available")
        
        rule_item = output["items"][0]
        rule_name = rule_item.get("name", name)
        readme_hash = rule_item.get("readme", "")
        
        if not readme_hash:
            logger.warning(f"No README hash found for rule: {name}")
            return vo.RuleReadmeResponseVO(ruleName=rule_name, error=f"README not available for rule: {name}")
        
        try:
            readme_response = await utils.make_GET_API_call_to_CCow(f"{constants.URL_FETCH_FILE_BY_HASH}/{readme_hash}", ctx)
            logger.debug(f"README fetch response for rule {rule_name}: {readme_response}")
            
            if isinstance(readme_response, str) or "error" in readme_response:
                logger.error(f"Failed to fetch README content for rule {name}: {readme_response}")
                return vo.RuleReadmeResponseVO(ruleName=rule_name, error=f"Failed to fetch README content for rule: {name}")
            
            readme_text = ""
            if isinstance(readme_response, dict):
                file_content = readme_response.get("FileContent", "")
                if file_content:
                    try:
                        readme_text = base64.b64decode(file_content).decode('utf-8')
                    except Exception:
                        readme_text = file_content
                else:
                    logger.warning(f"No FileContent found in response for rule: {name}")
                    return vo.RuleReadmeResponseVO(ruleName=rule_name, error=f"README not available for rule: {name}")
            elif isinstance(readme_response, str):
                readme_text = readme_response
            
            if not readme_text:
                logger.warning(f"No README content found for rule: {name}")
                return vo.RuleReadmeResponseVO(ruleName=rule_name, error=f"README not available for rule: {name}")
            
            logger.debug(f"Successfully fetched README for rule: {rule_name}")
            return vo.RuleReadmeResponseVO(readmeText=readme_text, ruleName=rule_name)
            
        except Exception as fetch_error:
            logger.error(f"Failed to fetch README content for rule {name}: {fetch_error}")
            return vo.RuleReadmeResponseVO(ruleName=rule_name, error=f"Failed to fetch README content for rule: {name}")

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("fetch_rule_readme error: {}\n".format(e))
        return vo.RuleReadmeResponseVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_tasks(ctx: Context | None = None) -> vo.WorkflowTaskListVO:
    """
    Retrieve available workflow tasks.
    
    Tasks are predefined operations that can be executed in workflow nodes. They 
    typically handle external integrations, notifications, or complex operations.
    Tasks have inputs and outputs that can be mapped to other workflow components.
    
    Returns:
        - tasks (list[WorkflowTaskVO]): List of available workflow tasks with input/output specifications
            - id (str)
            - name (str)
            - displayable (str)
            - description (str)
            - inputs: [list[WorkflowTaskInputsVO]]
            - outputs: [list[WorkflowTaskOutputsVO]]

        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("list_workflow_prebuild_tasks: \n")

        output = await utils.make_GET_API_call_to_CCow(f"{constants.URL_WORKFLOW_PREBUILD_TASKS}?tags=MCP-WORKFLOW", ctx)
        logger.debug("workflow prebuild tasks output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow prebuild tasks error: {}\n".format(output))
            return vo.WorkflowTaskListVO(error="Facing internal error")

        tasks: list[vo.WorkflowTaskVO]=[]
        for item in output["items"]:
            if "name" in item:
                tasks.append(vo.WorkflowTaskVO.model_validate(item))
        
        logger.debug("modified tasks: {}\n".format(vo.WorkflowTaskListVO(tasks=tasks).model_dump()))

        return vo.WorkflowTaskListVO(tasks=tasks)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("prebuild tasks error: {}\n".format(e))
        return vo.WorkflowTaskListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_condition_categories(ctx: Context | None = None) -> vo.WorkflowConditionCategoryListVO:
    """
    Retrieve available workflow condition categories.
    
    Condition categories help organize workflow decision points by type. This is 
    useful for filtering and selecting appropriate conditions when building workflows.
    
    Returns:
        - Condition categories (list[WorkflowConditionCategoryItemVO]): List of condition categories
            - name (str): Name of the category.
        - error (Optional[str]): An error message if any issues occurred during retrieval. 
    """
    try:
        logger.info("list_workflow_condition_categories: \n")

        output=await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_CONDITION_CATEGORIES, ctx)
        logger.debug("workflow condition categories output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow condition categories error: {}\n".format(output))
            return vo.WorkflowConditionCategoryListVO(error="Facing internal error")
        
        conditionCategories: list[vo.WorkflowConditionCategoryItemVO]=[]
        for item in output["items"]:
            if "displayable" in item:
                conditionCategories.append(vo.WorkflowConditionCategoryItemVO.model_validate(item))
        
        logger.debug("modified condition categories: {}\n".format(vo.WorkflowConditionCategoryListVO(conditionCategories=conditionCategories).model_dump()))

        return vo.WorkflowConditionCategoryListVO(conditionCategories=conditionCategories)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow condition categories: {}\n".format(e))
        return vo.WorkflowConditionCategoryListVO(error="Facing internal error")

@mcp.tool()
async def list_workflow_conditions(ctx: Context | None = None) -> vo.WorkflowConditionListVO:
    """
    Retrieve available workflow conditions.
    
    Conditions are decision points in workflows that evaluate expressions or functions 
    to determine the flow path. They can use CEL expressions or predefined functions 
    to make branching decisions. Only active conditions are returned.
    
    Returns:
        - conditions (list[WorkflowConditionVO]): List of active workflow conditions with input/output specifications
            - categoryId (str)
            - desc (str)
            - displayable: (str)
            - inputs: [list[WorkflowInputsVO]]
            - outputs: [list[WorkflowOutputsVO]]
            - status: (str)

        - error (Optional[str]): An error message if any issues occurred during retrieval.
    """
    try:
        logger.info("list_workflow_conditions: \n")

        output=await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_CONDITIONS, ctx)
        logger.debug("workflow conditions output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("workflow conditions error: {}\n".format(output))
            return vo.WorkflowConditionListVO(error="Facing internal error")
        
        conditions: list[vo.WorkflowConditionVO]=[]
        for item in output["items"]:
            if "displayable" in item and item.get("status") == "Active":
                conditions.append(vo.WorkflowConditionVO.model_validate(item))
        
        logger.debug("modified conditions: {}\n".format(vo.WorkflowConditionListVO(conditions=conditions).model_dump()))

        return vo.WorkflowConditionListVO(conditions=conditions)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow conditions: {}\n".format(e))
        return vo.WorkflowConditionListVO(error="Facing internal error")

@mcp.tool()
async def fetch_workflow_resource_data(resource: str, ctx: Context | None = None) -> dict | str:
    """
    Fetch workflow resource data for a given resource type.
    
    Resources provide dynamic data that can be used as inputs in workflow nodes. 
    This function retrieves available data for a specific resource type.
    
    Args:
        resource: The resource type to fetch data for. Resource options: USER_BLOCK
        
    Returns:
        List of resource data items or error message
    """
    try:
        logger.info("list_user_blocks: \n")

        output=await utils.make_API_call_to_CCow({"resource":resource},constants.URL_WORKFLOW_RESOURCE_DATA, ctx=ctx)
        logger.debug("list_user_blocks outputs : {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output or "items" not in output:
            logger.error("list_user_blocks error: {}\n".format(output))
            return output
        
        return output
    
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("list_user_blocks error: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def list_workflows(ctx: Context | None = None) -> list | str:
    """
    Retrieve a list of all available workflow configurations.
    
    Returns:
        - List of workflow configuration items : Each item contains workflow metadata
        - Error message (str): If retrieval fails or an error occurs
    
    """
    try:
        logger.info("list_workflows: \n")

        output=await utils.make_GET_API_call_to_CCow("/v3/workflow-configs?fields=meta", ctx)
        logger.debug("list_workflows output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("list_workflows error: {}\n".format(output))
            return "Facing internal error"
        if "items" in output:
            for item in output["items"]:
                utils.trimWorkflowDetails(item)
                # utils.deleteKey(item,"domainId")
                # utils.deleteKey(item,"orgId")
                # utils.deleteKey(item,"groupId")
                # utils.deleteKey(item,"spec")
                # if "status" in item:
                #     utils.deleteKey(item["status"],"filePathHash")
        # output["items"]=[]
        logger.debug("list_workflows output: {}\n".format(output))
        return output["items"]
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("list_workflows: {}\n".format(e))
        return "Facing internal error"


@mcp.tool()
async def get_workflow_by_name(name: str, ctx: Context | None = None) -> dict | str:
    """
        Get a workflow configuration by its name (exact, case-sensitive match).

        Args:
            - name (str): workflow name to search
    """
    try:
        logger.info(f"get_workflow_by_name: {name}\n")

        output = await utils.make_GET_API_call_to_CCow(f"/v3/workflow-configs?name={name}", ctx)
        logger.debug("get_workflow_by_name output: {}\n".format(output))

        if isinstance(output, str) or  "error" in output:
            logger.error("get_workflow_by_name error: {}\n".format(output))
            return "Facing internal error"
        if "items" in output and isinstance(output["items"], list):
            for item in output["items"]:
                utils.trimWorkflowDetails(item, True)
            if len(output["items"]) > 0:
                return output["items"][0]
            return "No workflow found with the given name"
        return "Facing internal error"
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("get_workflow_by_name: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def fetch_workflow_details(id:str, ctx: Context | None = None) -> dict | str:
    """
        Args:
            - id (str): workflow id. This can be fetched from path /status/id of 'get_workflows' output
    """
    try:
        logger.info(f"fetch_workflow_details: {id}\n")

        output=await utils.make_GET_API_call_to_CCow("/v3/workflow-configs/"+id, ctx)
        logger.debug("fetch_workflow_details output: {}\n".format(output))
        
        if isinstance(output, str) or  "error" in output:
            logger.error("fetch_workflow_details error: {}\n".format(output))
            return "Facing internal error"
        return output
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("fetch_workflow_details: {}\n".format(e))
        return "Facing internal error"

@mcp.tool()
async def list_workflow_predefined_variables(ctx: Context | None = None) -> vo.WorkflowPredefinedVariableListVO:
    """
    Retrieve available predefined variables for workflow configuration.
    
    Predefined variables are system-level variables that can be used in workflow 
    configurations. These system-level variables are mapped to specific operations. When you set a value for a predefined variable, 
    it automatically triggers the associated system operation (like sending workflow failure notifications).
    Example:
        - Sending workflow failure notifications to specific users
        - Sending workflow failure notifications to admin
    Returns:
        - items (list[WorkflowPredefinedVariableVO]): A list of predefined variables.
            - id (str): Unique identifier of the predefined variable
            - type (str): Data type of the variable (e.g., Text, Boolean)
            - name (str): Name of the predefined variable
        - error (Optional[str]): An error message if any issues occurred during retrieval.
    """
    try:
        logger.info("list_workflow_predefined_variables: \n")

        output = await utils.make_GET_API_call_to_CCow(constants.URL_WORKFLOW_PREDEFINED_VARIABLES, ctx)
        logger.debug("workflow predefined variables output: {}\n".format(output))
        
        if isinstance(output, str) or "error" in output:
            logger.error(f"Failed to fetch predefined variables: {output}")
            return vo.WorkflowPredefinedVariableListVO(error="Failed to retrieve predefined variables")
        
        items = []
        for item in output.get("items", []):
            if "id" in item and "type" in item and "name" in item:
                items.append(vo.WorkflowPredefinedVariableVO.model_validate(item))
        
        logger.debug("modified predefined variables: {}\n".format(vo.WorkflowPredefinedVariableListVO(items=items).model_dump()))

        return vo.WorkflowPredefinedVariableListVO(items=items)
    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error("workflow predefined variables: {}\n".format(e))
        return vo.WorkflowPredefinedVariableListVO(error="Facing internal error")

