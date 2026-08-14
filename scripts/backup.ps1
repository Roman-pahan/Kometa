# Забирает данные сайта на этот компьютер: базу целиком и вложения верификации.
#
# Копия складывается в папку с датой, старые копии не трогаются — если сегодня
# что-то удалили по ошибке, вчерашняя копия всё ещё лежит рядом.
#
# Запуск вручную:
#   powershell -ExecutionPolicy Bypass -File backup.ps1
#
# Токен берётся из переменной KOMETA_BACKUP_TOKEN или из файла backup-token.txt
# рядом со скриптом. В git ни то, ни другое не попадает.

param(
    # Куда складывать. По умолчанию вне OneDrive: копия содержит паспортные
    # данные клиентов, и синхронизировать её с чужим облаком незачем.
    [string]$Destination = "C:\Kometa-backup",
    [string]$SiteUrl = "https://kometa.exchange",
    # Сколько копий хранить. Старые удаляются, чтобы диск не заполнился.
    [int]$Keep = 30
)

$ErrorActionPreference = "Stop"

# Читаем токен: сначала переменная окружения, потом файл рядом со скриптом.
$token = $env:KOMETA_BACKUP_TOKEN
if (-not $token) {
    $tokenFile = Join-Path $PSScriptRoot "backup-token.txt"
    if (Test-Path $tokenFile) { $token = (Get-Content $tokenFile -Raw).Trim() }
}
if (-not $token) {
    Write-Error "Нет токена. Положите его в backup-token.txt рядом со скриптом или в переменную KOMETA_BACKUP_TOKEN."
}

$headers = @{ "X-Backup-Token" = $token }
$stamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$folder = Join-Path $Destination $stamp
$uploads = Join-Path $folder "uploads"
New-Item -ItemType Directory -Force -Path $uploads | Out-Null

Write-Output "Забираю базу..."
$dbPath = Join-Path $folder "exchange.db"
Invoke-WebRequest -Uri "$SiteUrl/api/admin/backup/db" -Headers $headers -OutFile $dbPath -TimeoutSec 300
$dbSize = [math]::Round((Get-Item $dbPath).Length / 1KB, 1)
Write-Output "  база: $dbSize КБ"

Write-Output "Забираю вложения..."
$list = Invoke-RestMethod -Uri "$SiteUrl/api/admin/backup/files" -Headers $headers -TimeoutSec 60
$count = 0
foreach ($file in $list.files) {
    $target = Join-Path $uploads $file.name
    Invoke-WebRequest -Uri "$SiteUrl/api/admin/backup/file/$($file.name)" -Headers $headers -OutFile $target -TimeoutSec 300
    $count++
}
Write-Output "  вложений: $count"

# Отметка о том, что копия снята целиком: если скрипт оборвался, файла не будет
$report = [ordered]@{
    snapshot_at = (Get-Date).ToString("o")
    site        = $SiteUrl
    db_bytes    = (Get-Item $dbPath).Length
    files       = $count
}
$report | ConvertTo-Json | Set-Content -Path (Join-Path $folder "backup.json") -Encoding utf8

# Чистим старые копии, оставляя последние $Keep штук.
$all = Get-ChildItem -Path $Destination -Directory | Sort-Object Name -Descending
if ($all.Count -gt $Keep) {
    $all | Select-Object -Skip $Keep | ForEach-Object {
        Remove-Item -Recurse -Force $_.FullName
        Write-Output "  удалена старая копия: $($_.Name)"
    }
}

Write-Output "Готово: $folder"
