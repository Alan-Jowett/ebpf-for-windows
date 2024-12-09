# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

function Get-PackageVersion(
    [string]$packageName
) {
    $package = nuget list $packageName
    $packageLine = $package | Where-Object { $_ -match $packageName }
    $packageVersion = $packageLine -replace "$packageName\s+", ""
    return $packageVersion
}

function Update-VersionInVsFile(
    [string]$vs_file_path,
    [string]$version_number
) {
    # Read the contents of the file
    $vs_file_content = Get-Content $vs_file_path

    # Replace the version number in the file
    $vs_file_content = $vs_file_content -replace "<WDKVersion>.*</WDKVersion>", "<WDKVersion>$version_number</WDKVersion>"

    # Write the updated contents back to the file
    Set-Content $vs_file_path $vs_file_content

    # Print success message
    Write-Output "Updated WDK version in $vs_file_path to $version_number"
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

# Copy scripts\setup_build\packages.config.template to scripts\setup_build\packages.config and replace the version number
$packages_config_template = $PSScriptRoot + "\..\scripts\setup_build\packages.config.template"
$packages_config = $PSScriptRoot + "\..\scripts\setup_build\packages.config"

# Read the contents of the file
$packages_config_content = Get-Content $packages_config_template

# Replace the $(WDKVersion) with the version number
$packages_config_content = $packages_config_content -replace "\$\(WDKVersion\)", $wdk_version_number

# Write the updated contents back to the file
Set-Content $packages_config $packages_config_content

# Print success message
Write-Output "Updated WDK version in all files"