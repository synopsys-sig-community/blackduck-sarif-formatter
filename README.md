# blackduck-sarif-formatter
This action is used to create a Sarif -format report from Black Duck.

## Prerequisities
This action expects that Black Duck scan is done before running this action. You can use Black Duck official GitHub Action [Black Duck Security Scan](https://github.com/marketplace/actions/black-duck-security-scan) to run full or rapid scan.

**Rapid scan results**

When running Black Duck scan with RAPID mode and you need to run this action to get Sarif -format report, you need to remember to use following parameters:
* --detect.scan.output.path
* --detect.cleanup=false

If you are using the Black Duck official action to run the Black Duck analysis, you can set needed params (listed above) with following environment variable (see example below):
* DETECT_SCAN_OUTPUT_PATH
* DETECT_CLEANUP

With detect.scan.output.path you will set a output folder for RAPID scan results. Then you must give the same folder to this action with input param **blackduck_scanOutputPath** (see examle below). 
By setting the detect.cleanup to false, you will prevent Black Duck to remove the result json -file after scan is done. This action will use that json -file.

## Available Options
| Option name | Description | Default value | Required |
|-------------|-------------|---------------|----------|
| blackduck_log_level | Logging level | DEBUG | false |
| blackduck_url | Black Duck URL| - | true |
| blackduck_apiToken | Black Duck Access token | - | true |
| blackduck_project | Black Duck project name | ${{github.repository}} | false |
| blackduck_version | Black Duck project version name | ${{github.ref_name}} | false |
| blackduck_policy_categories | Comma separated list of policy categories, which violations will affect. Options are [COMPONENT,SECURITY,LICENSE,UNCATEGORIZED,OPERATIONAL] | SECURITY,LICENSE | false |
| blackduck_outputFile | Filename with path where it will be created, example: github.workspace/blackduckFindings.sarif.json | ${{github.workspace}}/blackduckFindings.sarif.json | false
| blackduck_policies | If given, policy information is added | false | false |
| blackduck_scan_full | false for rapid scan results and true for intelligent scan | false | false |
| blackduck_scanOutputPath | If blackduck_scan_full = false, then this is required. Rapid scan output folder. You must specify scan output folder with --detect.scan.output.path when running the Rapid scan with Black Duck and then give the same folder here, if you want to have rapid scan results as a sarif format report.| ${{github.repository}}/bd_scan | false |
| blackduck_iac | If given, iac findings are added | false | false |
| blackduck_toolname_for_sarif_full | Given name is used for sarif tool name for Black Duck full scan results. Default is Synopsys Black Duck Intelligent | Synopsys Black Duck Intelligent  | false |
| blackduck_toolname_for_sarif_rapid | Given name is used for sarif tool name for Black Duck rapid scan results. Default is Synopsys Black Duck Rapid | Synopsys Black Duck Rapid | false

## Usage examples
Get Sarif format report from full Black Duck scan.
```yaml
       #------------Black Duck full------------------------#
    - name: Black Duck Analysis with black-duck-security-scan
      uses: blackduck-inc/black-duck-security-scan@v2
      with:
        blackducksca_token: ${{ secrets.blackduck_token }}
        blackducksca_url: ${{ secrets.blackduck_url }}
        blackducksca_scan_full: true
        blackducksca_fixpr_enabled: false
        blackducksca_fixpr_maxCount: 10
        blackducksca_fixpr_filter_severities: 'CRITICAL,HIGH,MEDIUM'
        blackducksca_scan_failure_severities: NONE
        github_token: ${{secrets.GITHUB_TOKEN}} # Mandatory when blackduck_fixpr_enabled is set to 'true'
      env:
        DETECT_PROJECT_NAME: ${{github.repository}}
        DETECT_PROJECT_VERSION_NAME: ${{github.ref_name}}
        DETECT_CODE_LOCATION_NAME: ${{github.repository}}-${{github.ref_name}}
        DETECT_TIMEOUT: "7200"
        DETECT_DETECTOR_SEARCH_DEPTH: "20"
        DETECT_DETECTOR_SEARCH_CONTINUE: "true"
        DETECT_EXCLUDED_DIRECTORIES_SEARCH_DEPTH: "20"
        DETECT_EXCLUDED_DIRECTORIES: node_modules,detect,.bridge
        DETECT_PUB_DEPENDENCY_TYPES_EXCLUDE: DEV
        DETECT_NPM_DEPENDENCY_TYPES_EXCLUDED: DEV
        DETECT_TOOLS: "ALL,IAC_SCAN" #All is not activating IaC scan, it needs to be activate separately with IAC_SCAN
      continue-on-error: true

    - uses: synopsys-sig-community/blackduck-sarif-formatter@main
      with:
        blackduck_url: ${{ secrets.blackduck_url }}
        blackduck_project: ${{ inputs.blackduck_project }}
        blackduck_version: ${{inputs.blackduck_version}}
        blackduck_apiToken: ${{ secrets.blackduck_token }}
        blackduck_scan_full: true
        blackduck_outputFile: ${{github.workspace}}/blackduck-sarif.json
        blackduck_scanOutputPath: ${{github.workspace}}/bd_scan
        blackduck_policies: true
        blackduck_log_level: INFO
        blackduck_policy_categories: SECURITY,LICENSE
        blackduck_iac: false
        blackduck_toolname_for_sarif_full: "Black Duck Intelligent"

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: blackduck-sarif.json
      continue-on-error: true
```

**Rapid Scan**

Get Sarif format report from Rapid Black Duck scan.
```yaml
       #------------Black Duck Rapid------------------------#
    - name: Black Duck Analysis with black-duck-security-scan
      uses: blackduck-inc/black-duck-security-scan@v2
      with:
        blackducksca_token: ${{ secrets.blackduck_token }}
        blackducksca_url: ${{ secrets.blackduck_url }}
        blackducksca_scan_full: false
        blackducksca_fixpr_enabled: false
        blackducksca_fixpr_maxCount: 10
        blackducksca_fixpr_filter_severities: 'CRITICAL,HIGH,MEDIUM'
        blackducksca_scan_failure_severities: NONE
        github_token: ${{secrets.GITHUB_TOKEN}} # Mandatory when blackduck_fixpr_enabled is set to 'true'
      env:
        DETECT_PROJECT_NAME: ${{github.repository}}
        DETECT_PROJECT_VERSION_NAME: ${{github.ref_name}}
        DETECT_CODE_LOCATION_NAME: ${{github.repository}}-${{github.ref_name}}
        DETECT_SCAN_OUTPUT_PATH: ${{github.workspace}}/bd_scan # This needs to be set, because of RAPID scan results
        DETECT_CLEANUP: "false" # This needs to be set, because of RAPID scan results
        DETECT_TIMEOUT: "7200"
        DETECT_DETECTOR_SEARCH_DEPTH: "20"
        DETECT_DETECTOR_SEARCH_CONTINUE: "true"
        DETECT_EXCLUDED_DIRECTORIES_SEARCH_DEPTH: "20"
        DETECT_EXCLUDED_DIRECTORIES: node_modules
        DETECT_BLACKDUCK_SIGNATURE_EXCLUSION_NAME_PATTERNS: detect.jar
        DETECT_NPM_DEPENDENCY_TYPES_EXCLUDED: DEV
        DETECT_TOOLS: "ALL,IAC_SCAN" #All is not activating IaC scan, it needs to be activate separately with IAC_SCAN
      continue-on-error: true

    - uses: synopsys-sig-community/blackduck-sarif-formatter@main
      with:
        blackduck_url: ${{ secrets.blackduck_url }}
        blackduck_apiToken: ${{ secrets.blackduck_token }}
        blackduck_scan_full: false
        blackduck_outputFile: ${{github.workspace}}/blackduck-sarif.json
        blackduck_scanOutputPath: ${{github.workspace}}/bd_scan
        blackduck_policies: true
        blackduck_log_level: INFO
        blackduck_policy_categories: SECURITY,LICENSE
        blackduck_toolname_for_sarif_rapid: Synopsys Black Duck Rapid

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v4
      with:
        sarif_file: blackduck-sarif.json
      continue-on-error: true
```

## Example pictures

**Black Duck scan results on the list**

![Black Duck scan results on the list.](/examples/BD_results_list.GIF)

**Black Duck Rapid scan results**

![Result from Black Duck Rapid scan.](/examples/BD_Rapid_result.GIF)

**Black Duck Full scan results**

![Result from Black Duck Full scan.](/examples/BD_full_result.GIF)

**Black Duck license violation**

![Result from Black Duck license violation.](/examples/BD_license_violation.GIF)