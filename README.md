# Brute Force IP Blocker
Esta aplicación tiene como proposito principal evitar que piratas informáticos realizen ataques de fuerza bruta para obtener accesso ya sea a escritorio remoto, servidores de archivos o bases de datos como SQL Server

![image](https://user-images.githubusercontent.com/75038053/176223716-3410aa9b-86b2-4883-a2e5-e2596ff5527c.png)

¿Como detecta los inicios de sesión erroneos?
El programa lee todos los eventos de seguridad y obtiene las IPs de los eventos del tipo "Microsoft-Windows-Security-Auditing".

Funciones de la aplicacion:
 * Puede obtener todas las IPs que tuvieron un inicio de sesión incorrecto y mostrarlas al usuario.
 * Puede bloquear mediante el Firewall de Windows Defender toda la lista de IPs mostradas al usuario.
 * Cuenta con un modo de escaneo continuo, que a cada cierto intervalo de tiempo configurable lee los eventos de seguridad y bloquea automaticamente las nuevas IPs infractoras.
 * Se puede activar una opcion que permite vaciar automaticamente los eventos de seguridad una vez se hallan bloqueado las IPs infractoras para disminuir el costo de recursos que implica analiazar miles de registros cada vez que se ejecute el escaneo.
