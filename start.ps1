param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Args
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
# Print header
& "$scriptDir\scripts\print_header.ps1"
# Run python scanner
python "$scriptDir\reconshell.py" @Args
