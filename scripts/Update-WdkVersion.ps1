# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

function Get-PackageVersion(
    [string]$packageName
) {
    if ([string]::IsNullOrWhiteSpace($packageName)) {
        throw "Package name cannot be empty"
    }

    try {
        $package = nuget list $packageName
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to retrieve package information"
        }
        $packageLine = $package | Where-Object { $_ -match $packageName }
        if (-not $packageLine) {
            throw "Package '$packageName' not found"
        }
        if ($packageLine -is [array]) {
            Write-Warning "Multiple versions found. Using the first one."
            $packageLine = $packageLine[0]
        }
        $packageVersion = $packageLine -replace "$packageName\s+", ""
        if (-not ($packageVersion -match '^\d+\.\d+\.\d+\.\d+$')) {
            throw "Invalid version format: $packageVersion"
        }
        return $packageVersion
    }
    catch {
        throw "Failed to get package version: $_"
    }
}

function Update-VersionInVsFile(
    [string]$vs_file_path,
    [string]$version_number
) {
    if ([string]::IsNullOrWhiteSpace($vs_file_path)) {
        throw "File path cannot be empty"
    }
    if (-not ($version_number -match '^\d+\.\d+\.\d+\.\d+$')) {
        throw "Invalid version format: $version_number"
    }
    if (-not (Test-Path $vs_file_path)) {
        throw "File not found: $vs_file_path"
    }
    try {
        # Create backup
        $backup_path = "$vs_file_path.bak"
        Copy-Item $vs_file_path $backup_path -Force
        # Read the contents of the file
        $vs_file_content = Get-Content $vs_file_path
        # Replace the version number in the file
        $vs_file_content = $vs_file_content -replace "<WDKVersion>.*</WDKVersion>", "<WDKVersion>$version_number</WDKVersion>"
        # Write the updated contents back to the file
        Set-Content $vs_file_path $vs_file_content
        # Print success message
        Write-Output "Updated WDK version in $vs_file_path to $version_number"
    } catch {
        if (Test-Path $backup_path) {
            Copy-Item $backup_path $vs_file_path -Force
            Remove-Item $backup_path
        }
        throw "Failed to update version in file: $vs_file_path"
    }
}

function Update-TemplateFile(
    [string]$template_file_path,
    [string]$output_file_path,
    [string]$version_number
)
{
    # Read the contents of the file
    $template_file_content = Get-Content $template_file_path

    # Replace the version number in the file
    $template_file_content = $template_file_content -replace "\$\(WDKVersion\)", $version_number

    # Write the updated contents back to the file
    Set-Content $output_file_path $template_file_content

    # Print success message
    Write-Output "Updated WDK version in $output_file_path to $version_number"
}

# Paths relative to the root of the repository
$vs_files_to_update = @(
    "wdk.props",
    "tools\bpf2c\templates\kernel_mode_bpf2c.vcxproj",
    "tools\bpf2c\templates\user_mode_bpf2c.vcxproj"
)

# Get the current WDK version
$wdk_version_number = Get-PackageVersion "Microsoft.Windows.WDK.x64"

# Print the version number
Write-Output "Found WDK version: $wdk_version_number"

# Replace version in each VS file
foreach ($vs_file in $vs_files_to_update) {
    Write-Host "Updating WDK version in $vs_file"
    $vs_file = $PSScriptRoot + "\..\" + $vs_file
    Update-VersionInVsFile $vs_file $wdk_version_number
}

Update-TemplateFile -template_file_path "$PSScriptRoot\..\scripts\setup_build\packages.config.template" -output_file_path "$PSScriptRoot\..\scripts\setup_build\packages.config" -version_number $wdk_version_number

# Print success message
Write-Output "Updated WDK version in all files"