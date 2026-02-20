# Analyzing Workflow Runtime

## Overview
This document provides instructions for analyzing the runtime duration of CI/CD pipeline workflows. Understanding the time taken to execute each stage directly impacts code velocity and helps identify bottlenecks.

## Terminology
- **Workflow**: The automated process defined in `.github/workflows/`
- **Run**: A single execution instance of a workflow, triggered by an event (push, pull request, etc.)
- **Job**: An individual task within a run (e.g., build, test)
- **Run ID**: The unique numerical identifier for a specific workflow execution

## Prerequisites
Before starting, ensure you have:
1. [GitHub CLI](https://github.com/cli/cli#installation) installed and authenticated (`gh auth login`)
2. [PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.3) 7.0 or later
3. Access to the [ebpf-for-windows repository](https://github.com/microsoft/ebpf-for-windows)

## Steps to Analyze Workflow Duration
1. Obtain the run ID for the workflow from the [actions](https://github.com/microsoft/ebpf-for-windows/actions) section on GitHub.
   - Select the action you want to analyze.
   - Copy the run ID from the URL (the number that appears after the `/runs/` part of the URL).

2. Execute the following commands in PowerShell:
   ```powershell
   # Set the run ID (example: 5629176229)
   $run_id = "5629176229"

   # Retrieve job data from GitHub API
   $json_text = gh api `
     -H "Accept: application/vnd.github+json" `
     -H "X-GitHub-Api-Version: 2022-11-28" `
     "/repos/microsoft/ebpf-for-windows/actions/runs/$run_id/jobs"

   # Convert JSON to PowerShell objects
   $jobs = (ConvertFrom-Json $json_text).jobs

   # Extract and calculate job durations
   $output = $jobs | Select-Object name, `
     @{name="started_at"; expression={[datetime]::parse($_.started_at)}}, `
     @{name="completed_at"; expression={[datetime]::parse($_.completed_at)}}, `
     @{name="duration"; expression={$_.completed_at - $_.started_at}}

   # Display results in table format
   $output | Format-Table
   ```
   This produces a table with job name, start time, completion time, and duration for each job.

## Example Output
Sample output from the above commands:
```
name                                                     started_at           completed_at         duration
----                                                     ----------           ------------         --------
codeql                                                   7/29/2023 5:49:01 PM 7/29/2023 5:49:01 PM 00:00:00
cmake / build (Debug)                                    7/29/2023 5:49:13 PM 7/29/2023 6:10:20 PM 00:21:07
cmake / build (Release)                                  7/29/2023 5:49:11 PM 7/29/2023 6:11:35 PM 00:22:24
```

## Troubleshooting

### Common Issues
- **`gh: command not found`**: Ensure GitHub CLI is installed and in your PATH.
- **`unauthorized` or `401` error**: Run `gh auth login` to authenticate with GitHub.
- **Empty or missing job data**: Verify the run ID is correct and the workflow has completed.
- **Date parsing errors**: Ensure you're using PowerShell 7.0 or later for proper datetime handling.

## Tips for Analysis
- Use `$output | Sort-Object duration -Descending` to identify the longest-running jobs.
- Export results to CSV: `$output | Export-Csv -Path workflow_analysis.csv -NoTypeInformation`
- Compare multiple runs to identify performance trends over time.