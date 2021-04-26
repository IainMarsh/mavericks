"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'ip_reputation_1' block
    ip_reputation_1(container=container)

    # call 'ip_reputation_2' block
    ip_reputation_2(container=container)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.logon_ip1', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=add_artifact_1, name="ip_reputation_1")

    return

def ip_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_2() called')

    # collect data for 'ip_reputation_2' call

    parameters = []
    
    # build parameters list for 'ip_reputation_2' call
    parameters.append({
        'ip': "",
    })

    phantom.act(action="ip reputation", parameters=parameters, assets=['virustotal'], callback=update_artifact_1, name="ip_reputation_2")

    return

def add_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_artifact_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_artifact_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.status', 'ip_reputation_1:action_result.data.*.continent', 'ip_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)
    inputs_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:artifact:*.source_data_identifier', 'hunt_file_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_artifact_1' call
    for results_item_1 in results_data_1:
        for inputs_item_1 in inputs_data_1:
            if inputs_item_1[0]:
                parameters.append({
                    'name': "User created artifact",
                    'container_id': "",
                    'label': "event",
                    'source_data_identifier': inputs_item_1[0],
                    'cef_name': results_item_1[0],
                    'cef_value': results_item_1[1],
                    'cef_dictionary': "",
                    'contains': "",
                    'run_automation': "true",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': inputs_item_1[1]},
                })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom_playbook'], name="add_artifact_1", parent_action=action)

    return

def update_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_artifact_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_2:action_result.status', 'ip_reputation_2:action_result.data.*.continent', 'ip_reputation_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'update_artifact_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'artifact_id': results_item_1[0],
                'name': results_item_1[1],
                'label': "",
                'severity': "",
                'cef_json': "",
                'cef_types_json': "",
                'tags': "",
                'overwrite': "",
                'artifact_json': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom_playbook'], name="update_artifact_1", parent_action=action)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return