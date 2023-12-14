# -*- coding: utf-8 -*-
# This script will collect all vulnerabilites and licenses which have a policy violation.
import glob
import json
import logging
import argparse
import os
import re
import sys
import hashlib
import codecs
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
from datetime import datetime

__author__ = "Jouni Lehto"
__versionro__="0.2.1"

#Global variables
args = "" 
MAX_LIMIT=1000
toolName="Synopsys Black Duck Rapid"
supportedPackageManagerFiles = ["pom.xml","requirements.txt","package.json","package-lock.json",".\.csproj",".\.sln","go.mod","Gopkg.lock","gogradle.lock","vendor.json","vendor.conf"]
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

def get_rapid_scan_results():
    hub = HubInstance(args.url, api_token=args.token, insecure=False)
    filelist = glob.glob(args.scanOutputPath + "/*.json")
    if filelist:
        if len(filelist) <= 0:
            return None
        bd_rapid_output_file_glob = max(filelist, key=os.path.getmtime)
        if len(bd_rapid_output_file_glob) == 0:
            logging.error("BD-Scan-Action: ERROR: Unable to find output scan files in: " + args.scanOutputPath + "/*.json")
            return None

        bd_rapid_output_file = bd_rapid_output_file_glob
        with codecs.open(bd_rapid_output_file, "r", encoding="utf8", errors="ignore") as f:
            output_data = json.load(f)

        if len(output_data) <= 0 or '_meta' not in output_data[0] or 'href' not in output_data[0]['_meta']:
            return None

        developer_scan_url = output_data[0]['_meta']['href']
        logging.debug("DEBUG: Developer scan href: " + developer_scan_url)
        rapid_scan_results = get_json(hub, developer_scan_url)
        return rapid_scan_results
    else:
        raise Exception("Didn't find any RAPID scan result json files. Note, that you need to give --detect.cleanup=false, so that results are not removed after scan is done.")

def get_json(hub, url):
    url += f'?limit={MAX_LIMIT}'
    result = hub.execute_get(url).json()
    all_data = result
    if "totalCount" in result:
        total = result['totalCount']
        downloaded = MAX_LIMIT
        while total > downloaded:
            req_url = f"{url}&offset={downloaded}"
            result = hub.execute_get(req_url).json()
            all_data['items'] = all_data['items'] + result['items']
            downloaded += MAX_LIMIT
        return all_data
    else:
        raise Exception(f"BD-Scan-Action: ERROR: Unable to fetch developer scan '{url}' - note that these are limited lifetime and this process must run immediately following the rapid scan")

def addFindings():
    global args
    rules, results, ruleIds = [], [], []
    findings = get_rapid_scan_results()
    if findings and len(findings) > 0:
        components = findings["items"]
        for component in components:
            for vulnerability in component["policyViolationVulnerabilities"]:
                rule, result = {}, {}
                ruleId = vulnerability["name"]
                ## Adding vulnerabilities as a rule
                if not ruleId in ruleIds:
                    rule = {"id":ruleId, "helpUri": vulnerability['_meta']['href'], "shortDescription":{"text":f'{vulnerability["name"]}: {component["componentName"]}'}, 
                        "fullDescription":{"text":f'{vulnerability["description"][:1000] if vulnerability["description"] else "-"}', "markdown": f'{vulnerability["description"] if vulnerability["description"] else "-"}'},
                        "help":{"text":f'{vulnerability["description"] if vulnerability["description"] else "-"}', "markdown": getHelpMarkdown(component, vulnerability)},
                        "properties": {"security-severity": getSeverityScore(vulnerability), "tags": addTags(vulnerability, None)},
                        "defaultConfiguration":{"level":nativeSeverityToLevel(vulnerability['vulnSeverity'].lower())}}
                    rules.append(rule)
                    ruleIds.append(ruleId)
                ## Adding results for vulnerabilities
                result['message'] = {"text":f'{vulnerability["description"][:1000] if vulnerability["description"] else "-"}'}
                result['ruleId'] = ruleId
                locations = []
                #There might be several transient dependencies
                for dependencies in component["dependencyTrees"]:
                    logging.debug(dependencies)
                    if len(dependencies) > 0:
                        component_to_find = dependencies[0]
                        if len(dependencies) > 1:
                            component_to_find = dependencies[1]
                        fileWithPath, lineNumber = find_file_dependency_file((component_to_find.replace('/',':').split(':')[0]).replace('-','\-'))
                        if lineNumber: 
                            locations.append({"physicalLocation":{"artifactLocation":{"uri":f'{fileWithPath}'},"region":{"startLine":int(lineNumber)}}})
                        else:
                            locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
                result['locations'] = locations
                result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{vulnerability["name"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                results.append(result)
            for licenseViolation in component["policyViolationLicenses"]:
                for violatingPolicies in licenseViolation["violatingPolicies"]:
                    #Adding license violations as a separate issues
                    rule, result = {}, {}
                    ruleId = violatingPolicies["policyName"]
                    ## Adding vulnerabilities as a rule
                    if not ruleId in ruleIds:
                        logging.debug(violatingPolicies)
                        rule = {"id":ruleId, "helpUri": licenseViolation['_meta']['href'], "shortDescription":{"text":f'{violatingPolicies["policyName"]}: {component["componentName"]}'}, 
                            "fullDescription":{"text":f'{violatingPolicies["description"][:1000] if "description" in violatingPolicies else "-"}', "markdown": f'{violatingPolicies["description"] if "description" in violatingPolicies else "-"}'},
                            "help":{"text":f'{violatingPolicies["description"] if "description" in violatingPolicies else "-"}', "markdown": getHelpMarkdownLicense(component, licenseViolation)},
                            "properties": {"security-severity": nativeSeverityToNumber(violatingPolicies['policySeverity'].lower()), "tags": addLicenseTags()}, 
                            "defaultConfiguration":{"level":nativeSeverityToLevel(violatingPolicies['policySeverity'].lower())}}
                        rules.append(rule)
                        ruleIds.append(ruleId)
                    ## Adding results for vulnerabilities
                    result['message'] = {"text":f'{violatingPolicies["description"][:1000] if "description" in violatingPolicies else "-"}'}
                    result['ruleId'] = ruleId
                    locations = []
                    #There might be several transient dependencies
                    for dependencies in component["dependencyTrees"]:
                        logging.debug(dependencies)
                        if len(dependencies) > 0:
                            component_to_find = dependencies[0]
                            if len(dependencies) > 1:
                                component_to_find = dependencies[1]
                            fileWithPath, lineNumber = find_file_dependency_file((component_to_find.replace('/',':').split(':')[0]).replace('-','\-'))
                            if lineNumber: 
                                locations.append({"physicalLocation":{"artifactLocation":{"uri":f'{fileWithPath}'},"region":{"startLine":int(lineNumber)}}})
                            else:
                                locations.append({"physicalLocation":{"artifactLocation":{"uri":"not_found_from_package_manager_files"},"region":{"startLine":1}}})
                    result['locations'] = locations
                    result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{violatingPolicies["policyName"]}{component["componentName"]}').encode(encoding='UTF-8')).hexdigest()}
                    results.append(result)




    return results, rules

def getSeverityScore(vulnerability):
    return f'{vulnerability["overallScore"] if "overallScore" in vulnerability else nativeSeverityToNumber(vulnerability["vulnSeverity"].lower())}'

def getHelpMarkdownLicense(component, licenseViolation):
    messageText = ""
    messageText += f'## Description\n'
    messageText += f'**License name:**\t{licenseViolation["name"] if "name" in licenseViolation else "-"}\n'
    messageText += f'**License family:**\t{licenseViolation["licenseFamilyName"] if "licenseFamilyName" in licenseViolation else "-"}\n'
    messageText += f'**License violating policies:**\n'
    for violation in licenseViolation["violatingPolicies"]:
        messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**Policy name:**\t{violation["policyName"] if "policyName" in violation else "-"}\n\n'
        messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**Policy description:**\t{violation["description"] if "description" in violation else "-"}\n\n'
        messageText += f'&nbsp;&nbsp;&nbsp;&nbsp;**Policy severity:**\t{violation["policySeverity"] if "policySeverity" in violation else "-"}\n\n'
    messageText += f'[View component]({component["_meta"]["href"]})'

    return messageText

def getHelpMarkdown(component, vulnerability):
    messageText = ""
    
    bdsa_link = ""
    if vulnerability["name"].startswith("BDSA"):
        bdsa_link = f'[View BDSA record]({vulnerability["_meta"]["href"]}) \| '
    elif vulnerability["name"].startswith("CVE"):
        bdsa_link = f'[View BDSA record]({getLinksparam(vulnerability, "related-vulnerability", "href")}) \| '

    cve_link = ""
    if vulnerability["name"].startswith("CVE"):
        cve_link = f'[View CVE record]({vulnerability["_meta"]["href"]})'
    elif vulnerability["name"].startswith("BDSA"):
        cve_link = f'[View CVE record]({getLinksparam(vulnerability, "related-vulnerability", "href")})'

    if vulnerability["name"].startswith("BDSA"):
        messageText += f'**BDSA** {vulnerability["name"]}'
    else:
        messageText += f'**NVD** {vulnerability["name"]}'
    related_vuln = getLinksparam(vulnerability, "related-vulnerability", "href")
    if related_vuln:
        messageText += f' ({related_vuln.split("/")[-1]})'
    #Adding score
    messageText += f' **Score** { getSeverityScore(vulnerability)}/10'
    if "dependencyTrees" in component:
        messageText += "\n\n## Dependency tree\n"
        for dependencies in component["dependencyTrees"]:
            intents = ""
            for dependency in dependencies:
                messageText += f'{intents}* {dependency}\n'
                intents += "    "

    messageText += f'\n\n## Description\n{vulnerability["description"] if vulnerability["description"] else "-"}\n{bdsa_link if bdsa_link else ""}{cve_link if cve_link else ""}'
    messageText += f'\n\nPublished on {getDate(vulnerability, "publishedDate")}\nVendor Fix {getDate(vulnerability,"vendorFixDate")}'
    timeAfter = datetime.now()-datetime.strptime(vulnerability["publishedDate"], "%Y-%m-%dT%H:%M:%S.%fZ")
    messageText += f'\nVulnerability Age {timeAfter.days} Days.'    
    messageText += f'\n\n## Solution\n{vulnerability["solution"] if "solution" in vulnerability and vulnerability["solution"] else "No Solution"}'
    messageText += f'\n\n## Workaround\n{vulnerability["workaround"] if "workaround" in vulnerability and vulnerability["workaround"] else "No Workaround"}'
    if "transitiveUpgradeGuidance" in component and len(component["transitiveUpgradeGuidance"]) > 0:
        for transitiveUpgradeGuidance in component["transitiveUpgradeGuidance"]:
            messageText += "\n\n## Upgrade guidance for transient dependency\n"
            messageText += f'**Upgrade guidance for a component:**\t{transitiveUpgradeGuidance["externalId"]} to upgrade transient dependency component: {component["externalId"]}\n'
            if "shortTermUpgradeGuidance" in transitiveUpgradeGuidance:
                messageText += f'**Recommended short term upgrade to version:**\t{transitiveUpgradeGuidance["shortTermUpgradeGuidance"]["versionName"]}\n'
            if "longTermUpgradeGuidance" in transitiveUpgradeGuidance:
                messageText += f'**Recommended long term upgrade to version:**\t{transitiveUpgradeGuidance["longTermUpgradeGuidance"]["versionName"]}\n'
    if "shortTermUpgradeGuidance" in component or "longTermUpgradeGuidance" in component:
        messageText += "\n\n## Upgrade guidance\n"
        messageText += f'**Upgrade guidance for a component:**\t{component["externalId"]}\n'
        if "shortTermUpgradeGuidance" in component:
            messageText += f'**Recommended short term upgrade to version:**\t{component["shortTermUpgradeGuidance"]["versionName"]}\n'
        if "longTermUpgradeGuidance" in component:
            messageText += f'**Recommended long term upgrade to version:**\t{component["longTermUpgradeGuidance"]["versionName"]}\n'
        
    if args.policies:
        if "violatingPolicies" in component:
            messageText += "\n\n## Policy violations\n"
            for policy in component["violatingPolicies"]:
                messageText += f'**Policy name:**\t{policy["policyName"] if "policyName" in policy else "-"}\n'
                messageText += f'**Policy description:**\t{policy["description"] if "description" in policy else "-"}\n'
                messageText += f'**Policy severity:**\t{policy["policySeverity"] if "policySeverity" in policy else "-"}\n\n'

    if vulnerability:
        messageText += "\n\n## References\n"
        for cwe in vulnerability['cweIds']:
            messageText += f'* Common Weakness Enumeration: [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split("-")[-1]}.html)\n'
    return messageText

def getDate(vulnerability, whichDate):
    datetime_to_modify = None
    if whichDate in vulnerability and vulnerability[whichDate]:
       datetime_to_modify = datetime.strptime(vulnerability[whichDate], "%Y-%m-%dT%H:%M:%S.%fZ")
    if datetime_to_modify:
        return datetime.strftime(datetime_to_modify, "%B %d, %Y")
    return "-"

def addTags(vulnerability, policy_name):
    tags = []
    if vulnerability:
        cwes = []
        for cweId in vulnerability['cweIds']:
            cwes.append("external/cwe/" + cweId.split("/")[-1].lower())
        tags.extend(cwes)
    elif policy_name:
        tags.append(policy_name)
    if "vendorFixDate" in vulnerability:
        tags.append("official_fix")
    tags.append("security")
    return tags

def addLicenseTags():
    tags = []
    tags.append("LICENSE_VIOLATION")
    tags.append("security")
    return tags

def getLinksparam(data, relName, param):
    for metadata in data['_meta']['links']:
        if metadata['rel'] == relName:
            return metadata[param]

def checkOrigin(component):
    if "externalId" in component:
        return component["externalId"].replace(' ', '_')
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

def writeToFile(findingsInSarif, outputFile):
    f = open(outputFile, "w", encoding="utf8")
    f.write(json.dumps(findingsInSarif, indent=3))
    f.close()

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

if __name__ == '__main__':
    try:
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Black Duck rapid scan results to SARIF format."
        )
        #Parse commandline arguments
        parser.add_argument('--url', help="Baseurl for Black Duck Hub", required=True)
        parser.add_argument('--token', help="BD Access token", required=True)
        parser.add_argument('--scanOutputPath', help="Rapid scan output folder. You must specify scan output folder with --detect.scan.output.path \
            when running the Rapid scan with Black Duck and then give the same folder here, if you want to have reapid scan results as a sarif format report", required=False)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/bdFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--policies', help="true, policy information is added", default=False, type=str2bool)
        args = parser.parse_args()
        #Initializing the logger
        if args.log_level == "9": log_level = "DEBUG"
        elif args.log_level == "0": log_level = "INFO"
        else: log_level = args.log_level
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        #Printing out the version number
        logging.info("Black Duck rapid results to SARIF formatter version: " + __versionro__)

        if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f'Given params are: {args}')
        findings, rules = addFindings()
        sarif_json = getSarifJsonHeader()
        results = {}
        results['results'] = findings
        results['tool'] = getSarifJsonFooter(toolName, rules)
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
