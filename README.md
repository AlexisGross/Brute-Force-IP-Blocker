# Brute Force IP Blocker
Esta aplicación tiene como objetivo principal evitar que los piratas informáticos realicen ataques de fuerza bruta para obtener accesso ya sea por escritorio remoto, servidores de archivos o bases de datos como SQL Server

![image](https://user-images.githubusercontent.com/75038053/176223716-3410aa9b-86b2-4883-a2e5-e2596ff5527c.png)

### ¿Como detecta los inicios de sesión erroneos?

El programa lee todos los eventos de seguridad y obtiene las IPs de los eventos del tipo "Microsoft-Windows-Security-Auditing".

## Funciones de la aplicacion:
 * Puede obtener todas las IPs que tuvieron un inicio de sesión incorrecto y mostrarlas al usuario.
 * Puede bloquear mediante el Firewall de Windows Defender toda la lista de IPs mostradas al usuario.
 * Cuenta con un modo de escaneo continuo, que a cada cierto intervalo de tiempo configurable lee los eventos de seguridad y bloquea automaticamente las nuevas IPs infractoras.
 * Se puede activar una opcion que permite vaciar automaticamente los eventos de seguridad una vez se hallan bloqueado las IPs infractoras para disminuir el costo de recursos que implica analiazar miles de registros cada vez que se ejecute el escaneo.

## Requisitos para compilar el programa
 * Visual Studio 2019 o superior con la carga de trabajo "Desarrollo de escritorio de .NET" instalada.
 
## Pasos para compilar el programa
 * Abrir el proyecto en Visual Studio.
 * En el explorador de soluciones, hacer clic derecho sobre la solución y seleccionar "Restaurar paquetes de NuGet".
 * Hacer clic derecho sobre el proyecto y seleccionar "Publicar".
 * Hacer clic en "Agregar perfil de publicación" y seguir los pasos de configuracion.
 * Hacer clic en "Publicar"

## Registro de cambios:
### Release 1.1
 * El modo continuo ya es funcional.
 * Ahora se ignoran los eventos en los que no se proporcionan una IP.
 * Ahora se vacía correctamente el registro de seguridad.
 
### Release 1.0
 * Se ha optimizado el código.
 
 #### Problemas conocidos de esta versión:
 * El modo continuo no esta implementado.
 * El vaciado de los registros de seguridad corrompen los registros de Windows.
