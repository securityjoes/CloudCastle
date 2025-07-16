for /f "tokens=*" %u in ('aws iam list-users --query "Users[*].UserName" --output text') do @(
    echo Checking user: %u
    aws iam list-access-keys --user-name %u --query "AccessKeyMetadata[?Status=='Active'].AccessKeyId" --output text > keys.txt
    aws iam get-login-profile --user-name %u >nul 2>&1 && set CONSOLE_ACCESS=Yes || set CONSOLE_ACCESS=No
    findstr /R /C:"AKIA" keys.txt >nul && set HAS_KEYS=Yes || set HAS_KEYS=No
    if "%HAS_KEYS%"=="No" if "%CONSOLE_ACCESS%"=="No" (echo ❌ %u is DISABLED (No active keys, No console access)) else (echo ✅ %u is ACTIVE)
    echo -----------------------------------
)
del keys.txt
