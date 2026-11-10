# Fresh Windows 10/11 -> VeilProxy prerequisites. Run in an *elevated* PowerShell.
winget install -e --id Git.Git
winget install -e --id Python.Python.3.12
winget install -e --id OpenJS.NodeJS.LTS
winget install -e --id Rustlang.Rustup
winget install -e --id Microsoft.VisualStudio.2022.BuildTools --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
Write-Host "Done. Close and reopen PowerShell, then follow docs/INSTALL.md (Windows section)."
