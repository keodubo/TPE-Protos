# Protocolo de Monitoreo y Configuracion (PMC), version 1

## 1. Alcance

PMC permite que un cliente autenticado consulte metricas y modifique usuarios o
parametros de un proxy SOCKS5. Esta especificacion define el intercambio entre
cliente y servidor con independencia de los programas que lo implementen.

Las palabras "DEBE", "NO DEBE", "DEBERIA", "PUEDE" y "OPCIONAL" se interpretan
como se describe en RFC 2119.

## 2. Transporte y representacion

PMC utiliza una conexion TCP persistente. El cliente inicia el dialogo. Todos los
mensajes se codifican en US-ASCII y se dividen en lineas terminadas por `CRLF`
(los octetos `0x0D 0x0A`). Una linea completa no puede superar 512 octetos,
incluido el terminador.

Un pedido ocupa exactamente una linea. La linea comienza con el nombre de un
comando y este se extiende hasta el primer espacio (`SP`, octeto `0x20`) o hasta
`CRLF` si el comando no lleva argumentos. Los comandos distinguen mayusculas de
minusculas. Cuando hay argumentos, cada par de campos consecutivos se separa por
un unico `SP`; no se permiten espacios iniciales, finales ni campos vacios.

La notacion siguiente usa ABNF:

```abnf
SP          = %x20
CRLF        = %x0D.0A
DIGIT       = %x30-39
ALPHA       = %x41-5A / %x61-7A
VCHAR       = %x21-7E

name-char   = ALPHA / DIGIT / "_" / "-"
name        = 1*64name-char
secret      = 1*255VCHAR
key         = 1*64name-char
value       = 1*255VCHAR
uint        = 1*DIGIT

request     = hello / auth / add-user / del-user / list-users
            / metrics / get-config / set-config / quit

hello       = "HELLO" SP "1" CRLF
auth        = "AUTH" SP name SP secret CRLF
add-user    = "ADD-USER" SP name SP secret CRLF
del-user    = "DEL-USER" SP name CRLF
list-users  = "LIST-USERS" CRLF
metrics     = "METRICS" CRLF
get-config  = "GET-CONFIG" SP key CRLF
set-config  = "SET-CONFIG" SP key SP value CRLF
quit        = "QUIT" CRLF
```

Una linea que no cumpla la sintaxis o la aridad del comando es invalida.

## 3. Modelo de intercambio

Una conexion atraviesa tres estados: negociacion, autenticacion y operacion.

1. En negociacion, el primer pedido valido DEBE ser `HELLO 1`. El numero indica
   la version de PMC que el cliente solicita. Si el servidor acepta la version,
   responde `+OK 1` y pasa a autenticacion. Si no la acepta, responde
   `-ERR unsupported version` y cierra la conexion.
2. En autenticacion, el pedido valido es `AUTH` con una credencial de
   administrador. Si la credencial es valida, el servidor responde `+OK` y pasa
   a operacion. Si no lo es, responde `-ERR auth failed` y cierra la conexion.
3. En operacion, el cliente PUEDE enviar cero o mas pedidos operativos. El
   servidor produce una respuesta por cada pedido, en el mismo orden en que
   recibio los pedidos.

Antes de completar la autenticacion, un pedido que no corresponde al estado
actual recibe `-ERR not authenticated`. La conexion permanece en el mismo estado,
salvo en los casos de cierre indicados arriba.

El cliente PUEDE enviar varios pedidos completos sin esperar las respuestas
anteriores. Esta tecnica se denomina *pipelining* y no altera el orden de las
respuestas.

## 4. Formato de respuesta

La primera linea de toda respuesta tiene una de estas formas:

```abnf
success-line = "+OK" [SP response-data] CRLF
error-line   = "-ERR" SP reason CRLF
response-data = 1*(VCHAR / SP)
reason        = 1*(VCHAR / SP)
```

`+OK` indica que el pedido fue exitoso. `-ERR` indica que el pedido fue
rechazado; `reason` contiene el motivo. Una respuesta es simple cuando termina
en esa primera linea.

`LIST-USERS` y `METRICS` producen respuestas multilinea. Su primera linea es
`+OK N`, donde `N` es un entero decimal sin signo. A continuacion aparecen
exactamente `N` lineas de datos. Esas lineas pertenecen a la misma respuesta y
no son respuestas independientes.

## 5. Comandos operativos

### 5.1 ADD-USER

`ADD-USER name secret` incorpora una credencial utilizable por el proxy.

- Exito: `+OK`.
- Nombre ya existente: `-ERR user exists`.
- Capacidad de usuarios agotada: `-ERR limit reached`.
- Nombre o secreto invalido: `-ERR bad name`.

El alta exitosa afecta autenticaciones SOCKS5 posteriores sin reiniciar el
servidor.

### 5.2 DEL-USER

`DEL-USER name` elimina la credencial identificada por `name`.

- Exito: `+OK`.
- Nombre inexistente: `-ERR no such user`.
- Nombre invalido: `-ERR bad name`.

### 5.3 LIST-USERS

`LIST-USERS` devuelve los nombres de todos los usuarios configurados. La
respuesta exitosa tiene la forma siguiente:

```abnf
list-response = "+OK" SP uint CRLF *(name CRLF)
```

La cantidad de lineas `name` DEBE coincidir con el entero de la primera linea.
Si no hay usuarios, la respuesta es `+OK 0` y no le siguen lineas de datos.

### 5.4 METRICS

`METRICS` devuelve cinco contadores. La respuesta exitosa es `+OK 5`, seguida
por una linea por metrica con el formato `metric-name SP uint CRLF`, en este
orden:

1. `historic-connections`: conexiones SOCKS5 aceptadas desde el inicio del
   periodo de medicion.
2. `concurrent-connections`: conexiones SOCKS5 que permanecen abiertas.
3. `bytes-transferred`: octetos retransmitidos por el proxy, sumando ambos
   sentidos.
4. `configured-users`: usuarios SOCKS5 disponibles.
5. `failed-connections`: pedidos SOCKS5 que no lograron establecer la conexion
   solicitada.

Cada valor es un entero decimal sin signo.

### 5.5 GET-CONFIG

`GET-CONFIG key` consulta un parametro. Para una clave conocida, la respuesta es
`+OK value`. Una clave desconocida recibe `-ERR unknown key`.

La version 1 define una unica clave:

- `buffer-size`: cantidad de octetos reservados para cada buffer de una nueva
  conexion SOCKS5.

### 5.6 SET-CONFIG

`SET-CONFIG key value` cambia un parametro. El exito se informa con `+OK`.

Para `buffer-size`, `value` DEBE ser un entero decimal entre 22 y 1048576,
inclusive. El cambio se aplica a conexiones SOCKS5 creadas posteriormente; no
redimensiona conexiones existentes.

- Clave desconocida: `-ERR unknown key`.
- Valor invalido o fuera de rango: `-ERR bad value`.

### 5.7 QUIT

`QUIT` finaliza una sesion persistente. El servidor responde `+OK bye` y, una vez
enviada esa respuesta, cierra la conexion PMC. Un cliente que realiza una sola
operacion por conexion puede terminar la conexion TCP directamente y no necesita
enviar este comando.

## 6. Errores generales

- Una linea que supera 512 octetos recibe `-ERR line too long`.
- Un comando desconocido, un comando conocido con aridad incorrecta o un pedido
  no valido en el estado de operacion recibe `-ERR not implemented`.
- Los errores especificos de un comando tienen prioridad sobre los errores
  generales cuando el comando y su aridad pudieron reconocerse.
