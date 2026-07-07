# Protocolo de Monitoreo y Configuracion (PMC) v1

## Estado

Este documento especifica el protocolo PMC implementado por el servidor SOCKS5
del TPE 2026C1.

Las palabras clave "DEBE", "NO DEBE", "OBLIGATORIO", "DEBERIA", "NO DEBERIA",
"RECOMENDADO", "PUEDE" y "OPCIONAL" se interpretan segun RFC2119.

## 1. Generalidades

- Transporte: TCP.
- Socket pasivo: distinto del socket SOCKS5. Por defecto escucha en
  `127.0.0.1:8080`, configurable con `-L` y `-P`.
- Formato: texto orientado a lineas.
- Terminador de linea: `CRLF` (`\r\n`).
- Codificacion: US-ASCII de 7 bits.
- Orden de inicio: el cliente habla primero.
- Concurrencia: el servidor DEBE atender PMC de forma no bloqueante y
  multiplexada junto con SOCKS5.

El cliente de administracion (`bin/client`) PUEDE usar I/O bloqueante porque es
una aplicacion de terminal simple. El servidor NO DEBE depender de `netcat` como
cliente oficial.

## 2. Sintaxis general

```abnf
command    = word *(SP argument) CRLF
response   = ok-response / err-response
ok-response = "+OK" [SP text] CRLF
err-response = "-ERR" SP text CRLF
```

Reglas:

- Los argumentos se separan por un unico `SP` (`0x20`).
- `name` y `key` DEBEN matchear `[A-Za-z0-9_-]{1,64}`.
- `pass` y `value` DEBEN ser imprimibles sin espacios, longitud `1..255`.
- La longitud maxima de linea es 512 bytes, incluyendo `CRLF`.
- El servidor DEBE responder `-ERR` ante aridad, longitud o caracteres invalidos.

## 3. Handshake

Antes de cualquier comando operativo, el cliente DEBE completar:

```text
C: HELLO 1
S: +OK 1
C: AUTH <admin-user> <admin-pass>
S: +OK
```

Si la version no es soportada:

```text
S: -ERR unsupported version
```

Si la autenticacion falla:

```text
S: -ERR auth failed
```

Antes de `AUTH` exitoso, el servidor solo acepta `HELLO` y `AUTH`. Cualquier
otro comando DEBE recibir `-ERR not authenticated`.

## 4. Comandos implementados

| Comando | Respuesta de exito | Errores tipicos |
|---|---|---|
| `ADD-USER <name> <pass>` | `+OK` | `-ERR user exists`, `-ERR limit reached`, `-ERR bad name` |
| `DEL-USER <name>` | `+OK` | `-ERR bad name`, `-ERR no such user` |
| `LIST-USERS` | `+OK <N>` y luego `N` lineas `<name>` | `-ERR ...` |
| `METRICS` | `+OK 5` y luego 5 lineas `<key> <value>` | `-ERR ...` |
| `GET-CONFIG buffer-size` | `+OK <value>` | `-ERR unknown key` |
| `SET-CONFIG buffer-size <value>` | `+OK` | `-ERR unknown key`, `-ERR bad value` |
| `QUIT` | `+OK bye` y cierre de conexion | `-ERR ...` |

### 4.1 Metricas implementadas

`METRICS` devuelve exactamente cinco metricas:

- `historic-connections`
- `concurrent-connections`
- `bytes-transferred`
- `configured-users`
- `failed-connections`

Ejemplo:

```text
C: METRICS
S: +OK 5
S: historic-connections 1422
S: concurrent-connections 87
S: bytes-transferred 9123847
S: configured-users 4
S: failed-connections 3
```

### 4.2 Claves de configuracion implementadas

La unica clave de configuracion implementada es:

- `buffer-size`: tamano de buffer de I/O usado para nuevas conexiones.

Ejemplos:

```text
C: GET-CONFIG buffer-size
S: +OK 8192

C: SET-CONFIG buffer-size 32768
S: +OK
```

Claves como `log-level`, timeouts u otros parametros son extensiones futuras y
NO forman parte de las claves implementadas en PMC v1.

## 5. Respuestas multilinea

`LIST-USERS` y `METRICS` usan prefijo de cantidad. La primera linea indica el
numero exacto de lineas de datos que siguen.

```text
C: LIST-USERS
S: +OK 2
S: alice
S: bob
```

El cliente DEBE leer exactamente `N` lineas luego de `+OK <N>`.

## 6. Pipelining

El cliente PUEDE enviar varios comandos sin esperar cada respuesta. El servidor
DEBE responder en el mismo orden en que los comandos fueron recibidos.

## 7. Ejemplo de sesion completa

```text
C: HELLO 1
S: +OK 1
C: AUTH admin s3cr3t
S: +OK
C: ADD-USER pablito pass1234
S: +OK
C: LIST-USERS
S: +OK 1
S: pablito
C: METRICS
S: +OK 5
S: historic-connections 5
S: concurrent-connections 2
S: bytes-transferred 40960
S: configured-users 1
S: failed-connections 0
C: GET-CONFIG buffer-size
S: +OK 8192
C: SET-CONFIG buffer-size 32768
S: +OK
C: QUIT
S: +OK bye
```

## 8. Consideraciones no normativas

- El PMC no cifra el canal. El despliegue recomendado es loopback
  (`127.0.0.1`) o una red administrativa controlada.
- El servidor valida aridad y caracteres antes de modificar estado.
- Las metricas son volatiles; un reinicio del proceso reinicia los contadores.
