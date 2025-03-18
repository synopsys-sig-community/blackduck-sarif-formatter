# -*- coding: utf-8 -*-
# This script will collect all vulnerabilites and licenses which have a policy violation.
import json
import logging
import argparse
import sys
import os
import re
import hashlib
import codecs
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
import requests
from datetime import datetime

__author__ = "Jouni Lehto"
__versionro__="0.2.3"

#Global variables
args = "" 
MAX_LIMIT=1000

toolName="Synopsys Black Duck Intelligent"
supportedPackageManagerFiles = ["pom.xml","requirements.txt","package.json","package-lock.json",r".\.csproj",r".\.sln","go.mod","Gopkg.lock","gogradle.lock","vendor.json","vendor.conf"]
dependency_cache = dict()

def find_file_dependency_file(dependency):
    logging.debug(f"Searching {dependency} from {os.getcwd()}")
    if dependency not in dependency_cache:
        for dirpath, dirnames, filenames in os.walk(os.getcwd(), True):
            re_patterns = []
            for pattern in supportedPackageManagerFiles:
                re_patterns.append(re.compile(pattern))
            dependencyFiles = {e for e in filenames for pattern in re_patterns if re.search(pattern, e)}
            for dependencyFile in dependencyFiles:
                lineNumber = checkDependencyLineNro(f'{dirpath}{os.path.sep}{dependencyFile}', dependency)
                if lineNumber:
                    filepath = dirpath[re.search(re.escape(os.getcwd()), dirpath).end()+1::]
                    if filepath == "":
                        logging.debug(f'dependency {dependency} found from {filepath}{dependencyFile} at line {lineNumber}')
                        dependency_cache[dependency] = {"file": dependencyFile, "line": lineNumber}
                        return dependencyFile, lineNumber
                    else:
                        logging.debug(f'dependency {dependency} found from {filepath}{os.path.sep}{dependencyFile} at line {lineNumber}')
                        dependency_cache[dependency] = {"file": f'{filepath}{os.path.sep}{dependencyFile}', "line": lineNumber}
                        return f'{filepath}{os.path.sep}{dependencyFile}', lineNumber
        logging.debug(f'dependency {dependency} not found!')
    else:
        return dependency_cache[dependency]['file'], dependency_cache[dependency]['line']
    return None, None

def checkDependencyLineNro(filename, dependency):
    with codecs.open(filename, "r", encoding="utf8", errors="ignore") as dependencyFile:
        for num, line in enumerate(dependencyFile, 1):
            if re.search(rf'\b{dependency}\b', line, re.IGNORECASE):
                return num
    return None

def get_vulnerability_overview(hub, vulnerability):
    return hub.execute_get(vulnerability['_meta']['href']).json()

def get_version_components(hub, projectversion, limit=MAX_LIMIT):
    parameters={"filter":f'{createFilterForCompoents()}', "limit": limit}
    url = projectversion['_meta']['href'] + "/components"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
    response = requests.get(url, headers=headers, params=parameters, verify = not hub.config['insecure'])
    jsondata = response.json()
    return jsondata

def get_Dependency_paths(hub, projectID, projectversionID, originID):
    url = f"{hub.get_urlbase()}/api/project/{projectID}/version/{projectversionID}/origin/{originID}/dependency-paths"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.bill-of-materials-6+json'
    response = requests.get(url, headers=headers, verify = not hub.config['insecure'])
    jsondata = response.json()
    return jsondata

def createFilterForCompoents():
    policyCategories = args.policyCategories.split(',')
    policyCategoryOptions = ""
    for policyCategory in policyCategories:
        policyCategoryOptions += f'policyCategory:{policyCategory.strip().lower()},'
    return policyCategoryOptions[:-1]

def getLinksData(hub, data, relName):
    return hub.execute_get(f'{getLinksparam(data,relName,"href")}?limit={MAX_LIMIT}').json()

def getLinksparam(data, relName, param):
    for metadata in data['_meta']['links']:
        if metadata['rel'] == relName:
            return metadata[param]

def getPolicyRules(hub, data):
    policies = []
    for metadata in data['_meta']['links']:
        if metadata['rel'] == "policy-rule":
            policies.append(hub.execute_get(f'{metadata["href"]}?limit={MAX_LIMIT}').json())
    return policies

def addFindings():
    global args
    rules, results, ruleIds = [], [], []
    hub = HubInstance(args.url, api_token=args.token, insecure=False)
    version = hub.get_project_version_by_name(args.project, args.version)
    if version:
        projectVersionId = version["_meta"]["href"].split("/")[-1]
        projectId = version["_meta"]["href"].split("/")[-3]
        components = get_version_components(hub, version)['items']
        for component in components:
            if not component['componentType'] == "SUB_PROJECT":
                locations, dependency_tree, dependency_tree_matched = checkLocations(hub, projectId, projectVersionId, component)
                origin = checkOrigin(component)
                # logging.debug(f'component: {component}')
                policies = []
                if args.policies:
                    policy_status = getLinksData(hub, component, "policy-status")
                    if policy_status:
                        policy_rules = getPolicyRules(hub, policy_status)
                        if policy_rules:
                            for policy in policy_rules:
                                if policy["category"] in args.policyCategories.split(','): 
                                    policies.append(policy)
                component_vulnerabilities = getLinksData(hub, component, "vulnerabilities")['items']
                ruleId = ""
                # Creating sarif for vulnerabilities
                if component_vulnerabilities and len(component_vulnerabilities) > 0:
                    for vulnerability in component_vulnerabilities:
                        vulnerability = get_vulnerability_overview(hub, vulnerability)
                        rule, result = {}, {}
                        ruleId = f'{vulnerability["name"]+"-"+origin if origin else vulnerability["name"]}'
                        ## Adding vulnerabilities as a rule
                        if not ruleId in ruleIds:
                            rule = {"id":ruleId, "helpUri": vulnerability['_meta']['href'], "shortDescription":{"text":f'{vulnerability["name"]}: {component["componentName"]}'[:900]}, 
                                "fullDescription":{"text":f'{vulnerability["description"][:900] if vulnerability["description"] else "-"}', "markdown": f'{vulnerability["description"] if vulnerability["description"] else "-"}'},
                                "help":{"text":f'{vulnerability["description"] if vulnerability["description"] else "-"}', "markdown": getHelpMarkdown(policies, vulnerability, dependency_tree, dependency_tree_matched)},
                                "properties": {"security-severity": getSeverityScore(getSeverity(vulnerability)), "tags": addTags(vulnerability)},
                                "defaultConfiguration":{"level":nativeSeverityToLevel(getSeverity(vulnerability).lower())}}
                            rules.append(rule)
                            ruleIds.append(ruleId)
                        ## Adding results for vulnerabilities
                        result['message'] = {"text":f'{vulnerability["description"][:1000] if vulnerability["description"] else "-"}'}
                        result['ruleId'] = ruleId
                        if locations and len(locations) > 0:
                            result['locations'] = locations
                        result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{vulnerability["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                        results.append(result)
                # Creating sarif for policy violations
                if policies and len(policies) > 0:
                    for policy_violation in policies:
                        # Creating sarif for LICENSE type of policy violations
                        if policy_violation['category'] == "LICENSE":
                            rule, result = {}, {}
                            ruleId = f'{policy_violation["name"]+"-"+origin if origin else policy_violation["name"]}'
                            ## Adding policy as a rule
                            if not ruleId in ruleIds:
                                rule = {"id":ruleId, "helpUri": policy_violation['_meta']['href'], "shortDescription":{"text":f'{policy_violation["name"]}: {component["componentName"]}'[:900]}, 
                                    "fullDescription":{"text":f'{policy_violation["description"][:900] if "description" in policy_violation else "-"}', "markdown": f'{policy_violation["description"] if "description" in policy_violation else "-"}'},
                                    "help":{"text":f'{policy_violation["description"] if "description" in policy_violation else "-"}', "markdown": getHelpMarkdownLicense(component, policy_violation, dependency_tree, dependency_tree_matched)},
                                    "properties": {"security-severity": nativeSeverityToNumber(policy_violation['severity'].lower()), "tags": addLicenseTags()},
                                    "defaultConfiguration":{"level":nativeSeverityToLevel(policy_violation['severity'].lower())}}
                                rules.append(rule)
                                ruleIds.append(ruleId)
                            ## Adding results for policy violations
                            result['message'] = {"text":f'{policy_violation["description"][:1000] if "description" in policy_violation else "-"}'}
                            result['ruleId'] = ruleId
                            if locations and len(locations) > 0:
                                result['locations'] = locations
                            result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{policy_violation["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                            results.append(result)
        if args.add_iac:
            iac_results = getIACFindings(hub, projectId, projectVersionId)
            if len(iac_results) > 0:
                for iac_result in iac_results:
                    if not iac_result["ignored"]:
                        iac_locations = []
                        rule, result = {}, {}
                        ruleId = f'{iac_result["checkerId"]+"-"+iac_result["fileName"] if "fileName" in iac_result else iac_result["checkerId"]}'
                        ## Adding policy as a rule
                        if not ruleId in ruleIds:
                            rule = {"id":ruleId, "helpUri": iac_result['_meta']['href'], "shortDescription":{"text":f'{iac_result["summary"]} in {iac_result["fileName"]}'[:900]}, 
                                "fullDescription":{"text":f'{iac_result["description"][:900] if "description" in iac_result else "-"}', "markdown": f'{iac_result["description"] if "description" in iac_results else "-"}'},
                                "help":{"text":f'{iac_result["description"] if "description" in iac_result else "-"}', "markdown": getHelpMarkdownIAC(iac_result)},
                                "properties": {"security-severity": nativeSeverityToNumber(iac_result['severity']['level'].lower()), "tags": addIACTags()},
                                "defaultConfiguration":{"level":nativeSeverityToLevel(iac_result['severity']["level"].lower())}}
                            rules.append(rule)
                            ruleIds.append(ruleId)
                        ## Adding results for policy violations
                        result['message'] = {"text":f'{iac_result["description"][:1000] if "description" in iac_result else "-"}'}
                        result['ruleId'] = ruleId
                        iac_locations.append({"physicalLocation":{"artifactLocation":{"uri": iac_result["filePath"]},"region":{"startLine":int(iac_result["location"]["start"]["line"])}}})
                        if iac_locations and len(iac_locations) > 0:
                            result['locations'] = iac_locations
                        result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{iac_result["checkerId"]}{iac_result["fileName"]}').encode(encoding='UTF-8')).hexdigest()}
                        results.append(result)
    return results, rules

def getIACFindings(hub, projectId, projectVersionId):
    MAX_LIMT_IAC = 25
    all_iac_findings = []
    url = f"{hub.get_urlbase()}/api/projects/{projectId}/versions/{projectVersionId}/iac-issues?limit={MAX_LIMT_IAC}&offset=0"
    headers = hub.get_headers()
    headers['Accept'] = 'application/vnd.blackducksoftware.internal-1+json, application/json'
    response = requests.get(url, headers=headers, verify = not hub.config['insecure'])
    if response.status_code == 200:
        result = response.json()
        if "totalCount" in result:
            total = result["totalCount"]
            all_iac_findings = result["items"]
            downloaded = MAX_LIMT_IAC
            while total > downloaded:
                logging.debug(f"getting next page {downloaded}/{total}")
                url = f"{hub.get_urlbase()}/api/projects/{projectId}/versions/{projectVersionId}/iac-issues?limit={MAX_LIMT_IAC}&offset={downloaded}"
                headers = hub.get_headers()
                headers['Accept'] = 'application/vnd.blackducksoftware.internal-1+json, application/json'
                response = requests.get(url, headers=headers, verify = not hub.config['insecure'])
                all_iac_findings.extend(response.json()['items'])
                downloaded += MAX_LIMT_IAC
    return all_iac_findings

def getDependenciesForComponent(hub, projectId, projectVersionId, component):
    dependencies = []
    for origin in component["origins"]:
        originID = getLinksparam(origin, "origin", "href").split("/")[-1]
        dependency_paths = get_Dependency_paths(hub, projectId, projectVersionId, originID)
        if dependency_paths and dependency_paths['totalCount'] > 0:
            for dependency in dependency_paths['items']:
                paths = []
                for path in dependency['path']:
                    if "originId" in path and path['originId']:
                        paths.append(path['originId'])
                dependencies.append(paths)
    return dependencies

def checkLocations(hub,projectId,projectVersionId,component):
    matchedFiles = getLinksData(hub, component, "matched-files")
    locations, dependency_tree, dependency_tree_matched = [],[],[]
    if matchedFiles and matchedFiles['totalCount'] > 0:
        for matchFile in matchedFiles['items']:
            logging.debug(f'matchFile: {matchFile}')
            fileName = matchFile['filePath']['archiveContext'].split('!')[0]
            if not fileName:
                fileName = matchFile['filePath']['compositePathContext'].split('!')[0]
                if not fileName:
                    fileName = matchFile['filePath']['fileName']
            locations.append({"physicalLocation":{"artifactLocation":{"uri":f'{fileName}'},"region":{"startLine":1}}})
            dependency_tree_matched.append(matchFile['filePath']['compositePathContext'])
    else:
        dependencies = getDependenciesForComponent(hub, projectId, projectVersionId, component)
        if dependencies and len(dependencies) > 0:
            logging.debug(dependencies)
            testingDependencies = []
            if len(dependencies[0]) > 1:
                testingDependencies = dependencies[0][-2]
            else:
                testingDependencies = dependencies[0][0]
            componentTofind = None
            if testingDependencies and len(testingDependencies) > 1:
                componentTofind = re.split(r'[:/]',testingDependencies)[-2]
            else:
                componentTofind = re.split(r'[:/]',testingDependencies)[0]
            fileWithPath, lineNumber = find_file_dependency_file(componentTofind.replace("-", r"\-"))
            lineNro = 1
            if lineNumber: 
                lineNro = int(lineNumber)
            if fileWithPath:
                locations.append({"physicalLocation":{"artifactLocation":{"uri": fileWithPath.replace('\\','/')},"region":{"startLine":lineNro}}})
            else:
                locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
            dependency_tree.extend(dependencies)
        else:
            locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
    if not len(locations) > 0:
        locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
    return locations, dependency_tree, dependency_tree_matched

def getSeverity(vulnerability):
    if "severity" in vulnerability:
        return vulnerability["severity"]
    elif "cvss3" in vulnerability:
        return vulnerability["cvss3"]["severity"]
    elif "cvss2" in vulnerability:
        return vulnerability["cvss2"]["severity"]
    else:
        return "unspecified"

def getSeverityScore(vulnerability):
    return f'{vulnerability["overallScore"] if "overallScore" in vulnerability else nativeSeverityToNumber(getSeverity(vulnerability).lower())}'

def getHelpMarkdownIAC(iac_result):
    messageText = ""
    if iac_result:
        messageText += f'## {iac_result["summary"]}\n'
        messageText += f'{iac_result["description"] if "description" in iac_result else "-"}\n'
        messageText += f'## Severity\n'
        messageText += f'**Level:** {iac_result["severity"]["level"] if "severity" in iac_result else "-"}\t'
        messageText += f'**Impact:** {iac_result["severity"]["impact"] if "severity" in iac_result else "-"}\t'
        messageText += f'**Likelihood:** {iac_result["severity"]["likelihood"] if "severity" in iac_result else "-"}\n'
        messageText += f'## Remediation\n'
        messageText += f'{iac_result["remediation"] if "remediation" in iac_result else "-"}\n'
        messageText += f'## Location\n'
        messageText += f'**File Path:** {iac_result["filePath"] if "filePath" in iac_result else "-"}\n'
        messageText += f'**Start:** Line: {str(iac_result["location"]["start"]["line"]) +",  Column: "+ str(iac_result["location"]["start"]["column"]) if "location" in iac_result else "-"}\n'
        messageText += f'**End:** Line: {str(iac_result["location"]["end"]["line"]) +", Column: "+ str(iac_result["location"]["end"]["column"]) if "location" in iac_result else "-"}'

    return messageText

def getHelpMarkdownLicense(component, policy_violation, dependency_tree, dependency_tree_matched):
    messageText = ""
    messageText += f'## Policy description\n'
    messageText += f'**Policy name:**\t{policy_violation["name"] if "name" in policy_violation else "-"}\n'
    messageText += f'**Policy description:**\t{policy_violation["description"] if "description" in policy_violation else "-"}\n'
    messageText += f'**Policy severity:**\t{policy_violation["severity"] if "severity" in policy_violation else "-"}\n\n'
    messageText += "\n\n**Conditions**\n"
    if "expression" in policy_violation and len(policy_violation["expression"]["expressions"]) > 0:
        index_expressions = 1
        for expression in policy_violation["expression"]["expressions"]:
            messageText += f'{expression["displayName"]} {expression["operation"]} '
            if "data" in expression["parameters"]:
                index_data = 1
                for data in expression["parameters"]["data"]:
                    if "licenseFamilyName" in data:
                        messageText += data["licenseFamilyName"]
                    elif "licenseName" in data:
                        messageText += data["licenseName"]
                    elif "data" in data:
                        messageText += data["data"]
                    else:
                        messageText += "-"
                    if index_data < len(expression["parameters"]["data"]):
                        messageText += ', '
                    index_data += 1
            if index_expressions < len(policy_violation["expression"]["expressions"]):
                messageText += f' {policy_violation["expression"]["operator"]} '
            index_expressions += 1
    if "componentVersion" in component:
        messageText += f'\n\n[View component {component["componentName"]}]({component["componentVersion"]})\n'
    elif "component" in component:
        messageText += f'\n\n[View component {component["componentName"]}]({component["component"]})\n'

    messageText += f'## Component Licenses\n'
    if "licenses" in component and len(component["licenses"]) > 0:
        for license in component["licenses"]:
            messageText += f'**License name:**\t{license["licenseDisplay"] if "licenseDisplay" in license else "-"}\n'
            messageText += f'**License spdxId:**\t{license["spdxId"] if "spdxId" in license else "-"}\n'
            messageText += f'**License family name:**\t{license["licenseFamilyName"] if "licenseFamilyName" in license else "-"}\n'
            messageText += f'**License type:**\t{license["licenseType"] if "licenseType" in license else "-"}\n'
            if "licenseType" in license and license["licenseType"] == "DISJUNCTIVE":
                messageText += f'**Sub-Licenses:**\n'
                for disjunctiveLicense in license["licenses"]:
                    messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**License name:**\t{disjunctiveLicense["licenseDisplay"] if "licenseDisplay" in disjunctiveLicense else "-"}\n'
                    messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**License spdxId:**\t{disjunctiveLicense["spdxId"] if "spdxId" in disjunctiveLicense else "-"}\n'
                    messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**License family name:**\t{disjunctiveLicense["licenseFamilyName"] if "licenseFamilyName" in disjunctiveLicense else "-"}\n\n'

    if dependency_tree and len(dependency_tree) > 0:
        messageText += "\n\n## Dependency tree\n"
        for dependencyline in dependency_tree:
            intents = ""
            for dependency in dependencyline[::-1]:
                messageText += f'{intents}* {dependency}\n'
                intents += "    "
    if dependency_tree_matched and len(dependency_tree_matched) > 0:
        messageText += "\n\n## </>Source\n"
        for dependencyline in dependency_tree_matched:
            intents = ""
            for dependencies in dependencyline.split('#')[::-1]:
                for dependency in dependencies.split('!/'):
                    if dependency:
                        messageText += f'{intents}* {dependency}\n'
                        intents += "    "
    return messageText

def getHelpMarkdown(policies, vulnerability, dependency_tree, dependency_tree_matched):
    cvss_version = ""
    if "cvss3" in vulnerability:
        cvss_version = "cvss3"
    else:
        cvss_version = "cvss2"
    vector = f'{vulnerability[cvss_version]["vector"] if "vector" in vulnerability[cvss_version] else ""}'
    attackVector = f'{vulnerability[cvss_version]["attackVector"] if "attackVector" in vulnerability[cvss_version] else ""}'
    attackComplexity = f'{vulnerability[cvss_version]["attackComplexity"] if "attackComplexity" in vulnerability[cvss_version] else ""}'
    confidentialityImpact = f'{vulnerability[cvss_version]["confidentialityImpact"] if "confidentialityImpact" in vulnerability[cvss_version] else ""}'
    integrityImpact = f'{vulnerability[cvss_version]["integrityImpact"] if "integrityImpact" in vulnerability[cvss_version] else ""}'
    availabilityImpact = f'{vulnerability[cvss_version]["availabilityImpact"] if "availabilityImpact" in vulnerability[cvss_version] else ""}'
    privilegesRequired = f'{vulnerability[cvss_version]["privilegesRequired"] if "privilegesRequired" in vulnerability[cvss_version] else ""}'
    scope = f'{vulnerability[cvss_version]["scope"] if "scope" in vulnerability[cvss_version] else ""}'
    userInteraction = f'{vulnerability[cvss_version]["userInteraction"] if "userInteraction" in vulnerability[cvss_version] else ""}'
    
    bdsa_link = ""
    messageText = ""
    if vulnerability["source"] == "BDSA":
        bdsa_link = f"[View BDSA record]({vulnerability['_meta']['href']}) | "
    elif getLinksparam(vulnerability, "related-vulnerabilities", "label") == "BDSA":
        bdsa_link = f"[View BDSA record]({getLinksparam(vulnerability, 'related-vulnerabilities', 'href')}) | "
    cve_link = ""
    if vulnerability["source"] == "NVD":
        cve_link = f'[View CVE record]({vulnerability["_meta"]["href"]})'
    elif getLinksparam(vulnerability, "related-vulnerability", "label") == "NVD":
        cve_link = f'[View CVE record]({getLinksparam(vulnerability, "related-vulnerability", "href")})'

    messageText += f'**{vulnerability["source"]}** {vulnerability["_meta"]["href"].split("/")[-1]}'
    related_vuln = getLinksparam(vulnerability, "related-vulnerabilities", "label")
    if related_vuln:
        messageText += f' ({getLinksparam(vulnerability, "related-vulnerabilities", "href").split("/")[-1]})'
    #Adding score
    messageText += f' **Score** { getSeverityScore(vulnerability)}/10'
    #Adding dependency tree or location
    if dependency_tree and len(dependency_tree) > 0:
        messageText += "\n\n## Dependency tree\n"
        for dependencyline in dependency_tree:
            intents = ""
            for dependency in dependencyline[::-1]:
                messageText += f'{intents}* {dependency}\n'
                intents += "    "
    if dependency_tree_matched and len(dependency_tree_matched) > 0:
        messageText += "\n\n## </>Source\n"
        for dependencyline in dependency_tree_matched:
            intents = ""
            for dependencies in dependencyline.split('#')[::-1]:
                for dependency in dependencies.split('!/'):
                    if dependency:
                        messageText += f'{intents}* {dependency}\n'
                        intents += "    "

    if "technicalDescription" in vulnerability and vulnerability['technicalDescription']:
        messageText += f'\n\n## Technical Description\n{vulnerability["technicalDescription"] if vulnerability["technicalDescription"] else "-"}\n{bdsa_link if bdsa_link else ""}{cve_link if cve_link else ""}\n\n## Base Score Metrics (CVSS v3.x Metrics)\n|   |   |   |   |\n| :-- | :-- | :-- | :-- |\n| Attack vector | **{attackVector}** | Availability | **{availabilityImpact}** |\n| Attack complexity | **{attackComplexity}** | Confidentiality | **{confidentialityImpact}** |\n| Integrity | **{integrityImpact}** | Scope | **{scope}** |\n| Privileges required | **{privilegesRequired}** | User interaction | **{userInteraction}** |\n\n{vector}'
    else:
        #CVEs don't have technical description
        messageText += f'\n\n## Description\n{vulnerability["description"] if vulnerability["description"] else "-"}\n{bdsa_link if bdsa_link else ""}{cve_link if cve_link else ""}\n\n## Base Score Metrics (CVSS v3.x Metrics)\n|   |   |   |   |\n| :-- | :-- | :-- | :-- |\n| Attack vector | **{attackVector}** | Availability | **{availabilityImpact}** |\n| Attack complexity | **{attackComplexity}** | Confidentiality | **{confidentialityImpact}** |\n| Integrity | **{integrityImpact}** | Scope | **{scope}** |\n| Privileges required | **{privilegesRequired}** | User interaction | **{userInteraction}** |\n\n{vector}'
    messageText += f'\n\nPublished on {getDate(vulnerability, "publishedDate")}\nLast Modified {getDate(vulnerability,"updatedDate")}\nDisclosure {getDate(vulnerability,"disclosureDate")}\nExploit Available {getDate(vulnerability,"exploitPublishDate")}'
    timeAfter = datetime.now()-datetime.strptime(vulnerability["publishedDate"], "%Y-%m-%dT%H:%M:%S.%fZ")
    messageText += f'\nVulnerability Age {timeAfter.days} Days.' 
    messageText += f'\n\n## Solution\n{vulnerability["solution"] if "solution" in vulnerability and vulnerability["solution"] else "No Solution"}'
    messageText += f'\n\n## Workaround\n{vulnerability["workaround"] if "workaround" in vulnerability and vulnerability["workaround"] else "No Workaround"}'

    if policies:
        messageText += "\n\n## Policy violations\n"
        for policy in policies:
            messageText += f'**Policy name:**\t{policy["name"] if "name" in policy else "-"}\n'
            messageText += f'**Policy description:**\t{policy["description"] if "description" in policy else "-"}\n'
            messageText += f'**Policy severity:**\t{policy["severity"] if "severity" in policy else "-"}\n\n'
  
    if vulnerability:
        messageText += "\n\n## References\n"
        for metadata in vulnerability['_meta']['links']:
            if metadata['rel'] == "cwes":
                cwe = metadata["href"].split("/")[-1]
                messageText += f'* Common Weakness Enumeration: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split("-")[-1]}.html)\n'
    return messageText

def getDate(vulnerability, whichDate):
    datetime_to_modify = None
    if whichDate in vulnerability and vulnerability[whichDate]:
       datetime_to_modify = datetime.strptime(vulnerability[whichDate], "%Y-%m-%dT%H:%M:%S.%fZ")
    if datetime_to_modify:
        return datetime.strftime(datetime_to_modify, "%B %d, %Y")
    return "-"

def addTags(vulnerability):
    tags = []
    if vulnerability:
        cwes = []
        for metadata in vulnerability['_meta']['links']:
            if metadata['rel'] == "cwes":
                cwes.append("external/cwe/" + metadata["href"].split("/")[-1].lower())
        tags.extend(cwes)
        cvss_version = ""
        if "cvss3" in vulnerability:
            cvss_version = "cvss3"
        else:
            cvss_version = "cvss2"
        if "temporalMetrics" in vulnerability[cvss_version]:
            if vulnerability[cvss_version]['temporalMetrics']['remediationLevel'] == 'OFFICIAL_FIX':
                tags.append("official_fix")
    tags.append("SCA")
    tags.append("security")
    return tags

def addLicenseTags():
    tags = []
    tags.append("LICENSE_VIOLATION")
    tags.append("security")
    return tags

def addIACTags():
    tags = []
    tags.append("IAC")
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
        "major": "error", 
        "medium": "warning", 
        "minor": "warning", 
        "low": "note",
        "trivial": "note",
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
        "major": "8.9", 
        "medium": "6.8", 
        "minor": "6.8", 
        "low": "3.8",
        "trivial": "3.8",
        "info": "1.0",
        "unspecified": "0.0",
    }
    return switcher.get(argument, "6.8")

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getSarifJsonFooter(toolDriverName, rules):
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def writeToFile(findingsInSarif, outputFile, mode="w"):
    f = open(outputFile, mode, encoding="UTF-8")
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
            Options are [COMPONENT,SECURITY,LICENSE,UNCATEGORIZED,OPERATIONAL], default=\"SECURITY\"", default="SECURITY")
        parser.add_argument('--policies', help="true, policy information is added", default=False, type=str2bool)
        parser.add_argument('--add_iac', help="true, iac findings are added", default=False, type=str2bool)
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
        results['tool'] = getSarifJsonFooter("Synopsys Black Duck Intelligent", rules)
        runs = []
        runs.append(results)
        sarif_json['runs'] = runs
        if args.outputFile:
            writeToFile(sarif_json, args.outputFile)
        else:
            print(json.dumps(sarif_json, indent=3))
        end = timer()
        logging.info(f"Creating SARIF format took: {end - start} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        raise SystemError(e)
