# Script de Empaquetado - Ticket Chain para Windows
$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Compilando Ticket Chain en Release...    " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$rootDir = Split-Path -Parent $PSScriptRoot
Set-Location $rootDir

# 1. Compilar todos los binarios con optimizaciones de release
cargo build --release

$dist = "$rootDir\dist\TicketChain-Standalone"

# 2. Preparar carpeta de distribución
if (Test-Path $dist) {
    Remove-Item -Recurse -Force $dist
}
New-Item -ItemType Directory -Force -Path "$dist\keys" | Out-Null

# 3. Copiar ejecutable principal todo-en-uno
Copy-Item "$rootDir\target\release\TicketChain.exe" "$dist\" -Force
Write-Host " [OK] Copiado TicketChain.exe (Todo-en-uno)" -ForegroundColor Green

# 4. Copiar herramientas de soporte
$tools = @("audit", "cli", "keygen", "pubkey", "attack", "ticket_chain")
foreach ($t in $tools) {
    $src = "$rootDir\target\release\$t.exe"
    if (Test-Path $src) {
        Copy-Item $src "$dist\"
    }
}

# 5. Copiar datos y claves base
Copy-Item "$rootDir\users.json" "$dist\"
if (Test-Path "$rootDir\chain.json") {
    Copy-Item "$rootDir\chain.json" "$dist\"
}
if (Test-Path "$rootDir\keys") {
    Copy-Item "$rootDir\keys\*.key" "$dist\keys\" -ErrorAction SilentlyContinue
}

# 6. Crear Guía de Uso
@"
========================================================================
             TICKET CHAIN - SISTEMA DE CADENA DE CUSTODIA
========================================================================

INSTRUCCIONES DE USO:
--------------------
Solo tienes que hacer DOBLE CLIC sobre:
   ==> TicketChain.exe <==

¡Eso es todo!
- No requiere abrir consolas ni scripts.
- Si el servidor no esta activo, lo inicia automaticamente en segundo plano.
- Abre directamente la interfaz grafica de usuario.

ROLES Y CUENTAS INCLUIDAS:
--------------------------
1. 'admin'   : Acceso completo y pestana 'Gestion de usuarios' para crear
               nuevas cuentas de empleados con 1 clic (genera su par de claves).
2. 'walter'  : Rol reportante (solo ve sus propios tickets en 'Mis reportes').
3. 'ana'     : Rol analista (atiende, asigna y resuelve tickets).

HERRAMIENTAS AUXILIARES (OPCIONALES):
------------------------------------
- audit.exe  : Ejecutalo en cualquier momento para verificar la integridad
               matematica de la cadena de bloques offline.
- cli.exe    : Para interactuar por linea de comandos.
- attack.exe : Para demostrar la deteccion de fraudes o alteraciones.
========================================================================
"@ | Set-Content "$dist\LEEME.txt" -Encoding UTF8

# 7. Crear el archivo ZIP comprimido listo para distribuir
$zipPath = "$rootDir\dist\TicketChain-Windows.zip"
if (Test-Path $zipPath) {
    Remove-Item -Force $zipPath
}
Compress-Archive -Path "$dist\*" -DestinationPath $zipPath -CompressionLevel Optimal
Write-Host " [OK] Comprimido en: $zipPath" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Todo listo:" -ForegroundColor Cyan
Write-Host " - Carpeta: $dist\TicketChain.exe" -ForegroundColor Yellow
Write-Host " - Archivo ZIP: $zipPath" -ForegroundColor Yellow
Write-Host "==========================================" -ForegroundColor Cyan
