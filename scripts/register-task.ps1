# タスクスケジューラに「LockWatch scan」を登録する（docs/design.md §7）
#   pwsh -File scripts\register-task.ps1                  毎日 9:00（逃した回は次に起動したとき）
#   pwsh -File scripts\register-task.ps1 -At 13:30
#   pwsh -File scripts\register-task.ps1 -Data D:\lw      データの場所を渡す（既定は設定の data_dir）
#   pwsh -File scripts\register-task.ps1 -Unregister      消す
# リポジトリの .venv の pythonw.exe で動かすので、コンソールの窓は開かない。結果は <data>/last-run.log と、
# タスクの「前回の実行結果」（0 = 終わった、1 = LockWatch の誤り、2 = targets.json が無いなど、3 = 実行中、4 = osv-scanner が失敗）で見る。
param(
    [string]$At = "09:00",
    [string]$Data = "",
    [string]$Name = "LockWatch scan",
    [switch]$Unregister
)
$ErrorActionPreference = "Stop"

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    Write-Host "消しました: $Name"
    return
}

$repo = Split-Path -Parent $PSScriptRoot
$pythonw = Join-Path $repo ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pythonw)) {
    throw "$pythonw がありません。先にリポジトリで uv sync を実行してください"
}
if (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue)) {
    Write-Warning "osv-scanner が PATH にありません（設定 osv_scanner で場所を指定していれば問題ありません）"
}

$arguments = "-m lockwatch --log"
if ($Data) { $arguments += " --data `"$Data`"" }
$arguments += " scan"

$action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $repo
$daily = New-ScheduledTaskTrigger -Daily -At $At
# 優先度 7 = 通常より低い。逃した回は次に起動したときに動かす。ネットが無いときは動かさない
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7 -ExecutionTimeLimit (New-TimeSpan -Hours 1)
# ログオンしているときだけ動かす（パスワードを預けない）
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $Name -Action $action -Trigger $daily -Settings $settings `
    -Principal $principal -Description "lock ファイルを osv-scanner にかけ、脆弱性の一覧を書く（$repo）" -Force | Out-Null
Write-Host "登録しました: $Name（毎日 $At）"
Write-Host "  $pythonw $arguments"
