# PowerShell script to install Password-Manager-Console-Application
Write-Host "Starting installation of Password Manager Console Application..." -ForegroundColor Cyan

# Step 1: Define variables
$installDir = "$env:USERPROFILE\PasswordManagerInstall"
$repoUrl = "https://github.com/nejczgank/Password-Manager-Console-Application.git"
$vcpkgDir = "$installDir\vcpkg"
$exeName = "passwordManager.exe"
$exeDestDir = "$env:USERPROFILE\PasswordManagerBin"
$pathAddition = $exeDestDir

# Step 2: Create installation directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}
Set-Location $installDir

# Step 3: Clone the GitHub repository
if (-not (Test-Path "$installDir\Password-Manager-Console-Application")) {
    Write-Host "Cloning repository from $repoUrl..." -ForegroundColor Yellow
    git clone $repoUrl
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to clone repository. Please check your internet connection or Git installation." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Repository already cloned." -ForegroundColor Green
}
Set-Location "$installDir\Password-Manager-Console-Application"

# Step 4: Install vcpkg if not present
if (-not (Test-Path $vcpkgDir)) {
    Write-Host "Installing vcpkg..." -ForegroundColor Yellow
    git clone https://github.com/microsoft/vcpkg.git $vcpkgDir
    Set-Location $vcpkgDir
    .\bootstrap-vcpkg.bat
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to bootstrap vcpkg." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "vcpkg already installed." -ForegroundColor Green
}
Set-Location $vcpkgDir

# Step 5: Install OpenSSL and integrate vcpkg
Write-Host "Installing OpenSSL via vcpkg..." -ForegroundColor Yellow
.\vcpkg install openssl:x64-windows
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install OpenSSL." -ForegroundColor Red
    exit 1
}
Write-Host "Integrating vcpkg with Visual Studio..." -ForegroundColor Yellow
.\vcpkg integrate install
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to integrate vcpkg." -ForegroundColor Red
    exit 1
}

# Step 6: Build the project (assuming a .sln file exists)
Set-Location "$installDir\Password-Manager-Console-Application"
$solutionFile = Get-ChildItem -Filter "*.sln" | Select-Object -First 1
if (-not $solutionFile) {
    Write-Host "No .sln file found. Please ensure the project includes a Visual Studio solution file." -ForegroundColor Red
    exit 1
}
Write-Host "Building the project..." -ForegroundColor Yellow
msbuild $solutionFile.Name -p:Configuration=Release -p:Platform=x64
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed. Ensure MSBuild is available and the project is correctly configured." -ForegroundColor Red
    exit 1
}

# Step 7: Locate and copy the executable
$exePath = Get-ChildItem -Path "x64\Release" -Filter $exeName -Recurse | Select-Object -First 1
if (-not $exePath) {
    Write-Host "Could not find $exeName in x64\Release. Build may have failed or executable name may differ." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $exeDestDir)) {
    New-Item -ItemType Directory -Path $exeDestDir | Out-Null
}
Copy-Item $exePath.FullName -Destination "$exeDestDir\$exeName"
Write-Host "Executable copied to $exeDestDir." -ForegroundColor Green

# Step 8: Add to system PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$pathAddition*") {
    Write-Host "Adding $exeName to system PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$pathAddition", "User")
    Write-Host "PATH updated. You may need to restart your terminal for changes to take effect." -ForegroundColor Yellow
} else {
    Write-Host "$exeName is already in PATH." -ForegroundColor Green
}

# Step 9: Notify user of success
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host "You can now run 'passwordManager.exe' from any command prompt." -ForegroundColor Green
Write-Host "If it doesn't work immediately, restart your terminal or computer to refresh the PATH." -ForegroundColor Yellow
