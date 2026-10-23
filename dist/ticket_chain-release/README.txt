========================================================================
             TICKET CHAIN - SISTEMA DE CADENA DE CUSTODIA
========================================================================

ESTRUCTURA DEL PAQUETE:
-----------------------
- INICIAR_SERVIDOR.bat   : Doble clic para arrancar el servidor en segundo plano.
- INICIAR_PORTAL.bat     : Doble clic para abrir la interfaz grÃ¡fica de usuario.
- ticket_chain.exe       : Binario del servidor.
- portal.exe             : Binario del portal grÃ¡fico (eframe / egui).
- cli.exe                : Cliente de lÃ­nea de comandos.
- audit.exe              : Auditor forense independiente de la cadena de bloques.
- keygen.exe             : Generador de pares de claves criptogrÃ¡ficas Ed25519.
- pubkey.exe             : Consultor de clave pÃºblica a partir de un archivo .key.
- attack.exe             : Demostrador didÃ¡ctico de ataques a la cadena.
- users.json             : Registro de usuarios autorizados y sus roles.
- keys/                  : Carpeta con las claves privadas individuales (.key).

ROLES DEL SISTEMA:
------------------
1. 'reportante' (ej. walter):
   - Solo puede enviar tickets.
   - Solo ve sus propios tickets creados ("Mis reportes").
   - NO puede ver tickets de otros usuarios.
   - NO puede asignarse ni resolverse tickets.

2. 'analista' (ej. ana):
   - Puede ver todos los tickets.
   - Puede asignarse tickets y resolverlos (regla de cuatro ojos: no puede
     asignarse o resolver un ticket que ella misma haya creado).

3. 'admin' (ej. admin):
   - Puede ver todos los tickets y auditar la cadena.
   - PestaÃ±a 'GestiÃ³n de usuarios' en el Portal: permite crear nuevas cuentas
     para nuevos empleados con un solo clic, generando automÃ¡ticamente su
     par de claves Ed25519 e inscribiÃ©ndolos en users.json sin tocar cÃ³digo.

AJUSTES MEDIANTE VARIABLES DE ENTORNO (OPCIONAL):
------------------------------------------------
- TC_BIND   : DirecciÃ³n IP y puerto donde escucha el servidor (por defecto 127.0.0.1:7878).
- TC_SERVER : DirecciÃ³n a la que se conectan los clientes (por defecto 127.0.0.1:7878).
- TC_DATA   : Ruta personalizada para datos (por defecto la carpeta del ejecutable).

========================================================================
