# -*- coding: utf-8 -*-
# This script will collect all vulnerabilites and licenses which have a policy violation.
import json
import logging
import argparse
import re
import sys
import hashlib
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
import requests

__author__ = "Jouni Lehto"
__versionro__="0.1.6"

#Global variables
args = "" 
MAX_LIMIT=1000

def get_version_components(hub, projectversion, limit=MAX_LIMIT):
    parameters={"filter":f'{createFilterForCompoents()}', "limit": limit}
    url = projectversion['_meta']['href'] + "/components"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
    response = requests.get(url, headers=headers, params=parameters, verify = not hub.config['insecure'])
    jsondata = response.json()
    return jsondata

def createFilterForCompoents():
    policyCategories = args.policyCategories.split(',')
    policyCategoryOptions = ""
    for policyCategory in policyCategories:
        policyCategoryOptions += f'policyCategory:{policyCategory.strip().lower()},'
    return policyCategoryOptions[:-1]

def getLinksData(hub, data, relName):
    return hub.execute_get(f'{getLinksUrl(data,relName)}?limit={MAX_LIMIT}').json()

def getLinksUrl(data, relName):
    for metadata in data['_meta']['links']:
        if metadata['rel'] == relName:
            return metadata['href']

def addFindings():
    global args
    rules, results, ruleIds = [], [], []
    hub = HubInstance(args.url, api_token=args.token, insecure=False)
    version = hub.get_project_version_by_name(args.project, args.version)
    if version:
        components = get_version_components(hub, version)['items']
        for component in components:
            component_vulnerabilities = getLinksData(hub, component, "vulnerabilities")['items']
            # Only Security type of policies have vulnerabilities, it might be that there is a 
            # license policy violation and that component doesn't have vulnerabilities
            ruleId = ""
            if len(component_vulnerabilities) > 0:
                for vulnerability in component_vulnerabilities:
                    rule, result = {}, {}
                    ruleId = vulnerability["name"]
                    ## Adding vulnerabilities as a rule
                    if not ruleId in ruleIds:
                        rule = {"id":ruleId, "helpUri": vulnerability['_meta']['href'], "shortDescription":{"text":f'{vulnerability["name"]}: {component["componentName"]}'}, 
                            "fullDescription":{"text":f'{vulnerability["description"][:1000] if vulnerability["description"] else "-"}', "markdown":f'{vulnerability["description"][:1000] if vulnerability["description"] else "-"}'},
                            "help":{"text":f'{vulnerability["description"] if vulnerability["description"] else "-"}', "markdown":f'{vulnerability["description"] if vulnerability["description"] else "-"}'},
                            "properties": {"category": checkOrigin(component), "security-severity": nativeSeverityToNumber(vulnerability["severity"].lower()), "tags": addTags(vulnerability["name"])},
                            "defaultConfiguration":{"level":nativeSeverityToLevel(vulnerability['severity'].lower())}}
                        rules.append(rule)
                        ruleIds.append(ruleId)
                    ## Adding results for vulnerabilities
                    bdLink = f'[See in Black Duck]({vulnerability["_meta"]["href"]})'
                    result['message'] = {"text": f'{bdLink}\n\n{vulnerability["name"]}'}
                    result['ruleId'] = ruleId
                    result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": "file:///" + checkOrigin(component)}}}]
                    result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{vulnerability["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                    results.append(result)
            if args.policies:
                component_policyStatuses = getLinksData(hub, component, "policy-status")
                if component_policyStatuses:
                    for component_policyStatus in component_policyStatuses['_meta']['links']:
                        policyInfo = hub.execute_get(f'{component_policyStatus["href"]}?limit={MAX_LIMIT}').json()
                        categories = re.sub(r"[\n\t\s]*", "", args.policyCategories)
                        if policyInfo["category"].lower() in categories.lower().split(','):
                            rule, result = {}, {}
                            ruleId = policyInfo["name"]
                            ## Adding policy as a rule
                            if not ruleId in ruleIds:
                                rule = {"id":ruleId, "helpUri": policyInfo['_meta']['href'], "shortDescription":{"text":f'{policyInfo["description"] if "description" in policyInfo else "-"}'}, 
                                    "fullDescription":{"text":f'{policyInfo["description"][:1000] if "description" in policyInfo else policyInfo["name"]}', "markdown":f'{policyInfo["description"][:1000] if "description" in policyInfo else policyInfo["name"]}'},
                                    "help":{"text":f'{policyInfo["description"] if "description" in policyInfo else policyInfo["name"]}', "markdown":f'{policyInfo["description"] if "description" in policyInfo else policyInfo["name"]}'},
                                    "properties": {"category":checkOrigin(component), "security-severity": nativeSeverityToNumber(policyInfo["severity"].lower()), "tags": addTags(policyInfo["name"])},
                                    "defaultConfiguration":{"level":nativeSeverityToLevel(policyInfo['severity'].lower())}}
                                rules.append(rule)
                                ruleIds.append(ruleId)
                            ## Adding results for policies
                            bdLink = f'[See in Black Duck]({component["component"]})'
                            result['message'] = {"text":f'{policyInfo["name"]}: {policyInfo["category"]}\n\n{bdLink}'}
                            result['ruleId'] = ruleId
                            result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": "file:///" + checkOrigin(component)}}}]
                            result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{policyInfo["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                            results.append(result)
    return results, rules

def addTags(cve):
    tags = []
    tags.append("security")
    return tags

def checkOrigin(component):
    if "origins" in component:
        if len(component["origins"]) > 0 and "externalId" in component["origins"][0]:
            return component["origins"][0]["externalId"].replace(' ', '_')
    return component["componentName"].replace(' ', '_')

# Changing the native severity into sarif defaultConfiguration level format
def nativeSeverityToLevel(argument): 
    switcher = { 
        "blocker": "error", 
        "critical": "error", 
        "high": "error", 
        "medium": "warning", 
        "low": "note",
        "info": "note",
        "unspecified": "note"
    }
    return switcher.get(argument, "warning")

# Changing the native severity into sarif security-severity format
def nativeSeverityToNumber(argument): 
    switcher = { 
        "blocker": "9.8", 
        "critical": "9.1", 
        "high": "8.9", 
        "medium": "6.8", 
        "low": "3.8",
        "info": "1.0",
        "unspecified": "0.0",
    }
    return switcher.get(argument, "6.8")

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getSarifJsonFooter(toolDriverName, rules):
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def writeToFile(findingsInSarif):
    f = open(args.outputFile, "w")
    f.write(json.dumps(findingsInSarif, indent=3))
    f.close()

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

if __name__ == '__main__':
    try:
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Black Duck results to SARIF format."
        )
        #Parse commandline arguments
        parser.add_argument('--url', help="Baseurl for Black Duck Hub", required=True)
        parser.add_argument('--token', help="BD Access token", required=True)
        parser.add_argument('--project', help="BD project name", required=True)
        parser.add_argument('--version', help="BD project version name", required=True)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/bdFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--policyCategories', help="Comma separated list of policy categories, which violations will affect. \
            Options are [COMPONENT,SECURITY,LICENSE,UNCATEGORIZED,OPERATIONAL], default=\"SECURITY,LICENSE\"", default="SECURITY,LICENSE")
        parser.add_argument('--policies', help="If given, policy information is added", default=False, type=str2bool)
        args = parser.parse_args()
        #Initializing the logger
        if args.log_level == "9": log_level = "DEBUG"
        elif args.log_level == "0": log_level = "INFO"
        else: log_level = args.log_level
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.info("Black Duck results to SARIF formatter version: " + __versionro__)
        if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f'Given params are: {args}')
        findings, rules = addFindings()
        sarif_json = getSarifJsonHeader()
        results = {}
        results['results'] = findings
        results['tool'] = getSarifJsonFooter("Synopsys Black Duck", rules)
        runs = []
        runs.append(results)
        sarif_json['runs'] = runs
        if args.outputFile:
            writeToFile(sarif_json)
        else:
            print(json.dumps(sarif_json, indent=3))
        end = timer()
        logging.info(f"Creating SARIF format took: {end - start} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
