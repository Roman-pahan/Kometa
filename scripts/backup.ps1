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
# База качается потоком, а не через -OutFile с -PassThru: в Windows PowerShell 5.1
# это сочетание падает с NullReferenceException, а заголовок ответа нам нужен.
$request = [System.Net.HttpWebRequest]::Create("$SiteUrl/api/admin/backup/db")
$request.Headers.Add("X-Backup-Token", $token)
$request.Timeout = 300000
$request.ReadWriteTimeout = 300000
$response = $request.GetResponse()
try {
    # Момент снимка: по нему сервер поймёт, что именно уже лежит здесь
    $snapshotAt = $response.Headers["X-Snapshot-At"]
    $input = $response.GetResponseStream()
    $output = [System.IO.File]::Create($dbPath)
    try { $input.CopyTo($output) } finally { $output.Close(); $input.Close() }
} finally { $response.Close() }
if (-not $snapshotAt) { Write-Error "Сервер не сообщил момент снимка — подтверждать нечего." }
$dbSize = [math]::Round((Get-Item $dbPath).Length / 1KB, 1)
Write-Output "  база: $dbSize КБ"

# Проверяем, что скачался настоящий файл базы, а не обрывок и не страница с
# ошибкой. Дальше идёт подтверждение, а его сервер понимает как разрешение
# стирать у себя — подтверждать нечитаемую копию нельзя.
$head = New-Object byte[] 16
$stream = [System.IO.File]::OpenRead($dbPath)
try { $null = $stream.Read($head, 0, 16) } finally { $stream.Close() }
$magic = [System.Text.Encoding]::ASCII.GetString($head)
if ($magic -ne "SQLite format 3`0") {
    Write-Error "Скачанный файл не похож на базу SQLite. Копия оставлена в $folder, на сервере ничего не тронуто."
}
if ((Get-Item $dbPath).Length -lt 20KB) {
    Write-Error "База подозрительно мала ($dbSize КБ). Копия оставлена в $folder, на сервере ничего не тронуто."
}

Write-Output "Забираю вложения..."
$list = Invoke-RestMethod -Uri "$SiteUrl/api/admin/backup/files" -Headers $headers -TimeoutSec 60
$received = @()
foreach ($file in $list.files) {
    $target = Join-Path $uploads $file.name
    Invoke-WebRequest -Uri "$SiteUrl/api/admin/backup/file/$($file.name)" -Headers $headers -OutFile $target -TimeoutSec 300 -UseBasicParsing
    # В подтверждение попадает только то, что реально легло на диск нужного размера
    if ((Test-Path $target) -and ((Get-Item $target).Length -eq $file.size)) { $received += $file.name }
}
$count = $received.Count
Write-Output "  вложений: $count"

# Говорим серверу, что копия на месте. Только после этого он что-то стирает —
# оборвался скрипт, не дошли файлы, кончилось место: подтверждения нет, и на
# сервере всё остаётся как было.
Write-Output "Подтверждаю получение..."
$confirmBody = @{ snapshot_at = $snapshotAt; files = $received } | ConvertTo-Json -Compress
$confirm = Invoke-RestMethod -Uri "$SiteUrl/api/admin/backup/confirm" -Method Post `
    -Headers ($headers + @{ "Content-Type" = "application/json" }) -Body $confirmBody -TimeoutSec 120
Write-Output "  с сервера убрано: заявок $($confirm.deleted_orders), фото $($confirm.deleted_photos)"

# Отметка о том, что копия снята целиком: если скрипт оборвался, файла не будет
$report = [ordered]@{
    snapshot_at     = $snapshotAt
    pulled_at       = (Get-Date).ToString("o")
    site            = $SiteUrl
    db_bytes        = (Get-Item $dbPath).Length
    files           = $count
    deleted_orders  = $confirm.deleted_orders
    deleted_photos  = $confirm.deleted_photos
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
