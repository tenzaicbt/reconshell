param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Args
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
& "$scriptDir\scripts\print_header.ps1"
python "$scriptDir\reconshell.py" @Args
