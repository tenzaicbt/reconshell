param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Args
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
python -B "$scriptDir\reconshell.py" @Args
