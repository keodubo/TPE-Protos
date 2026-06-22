# Protocolo de Monitoreo y Configuración (PMC) — Borrador v0

> **Estado:** BORRADOR. Documento "estilo RFC", agnóstico al lenguaje, para el
> protocolo propio de administración del servidor SOCKS5 del TPE.
> Pulir antes de la entrega; este draft fija la base decidida en el grilling
> (ver `DECISIONS.md` D1/D2). Las palabras clave DEBE/PUEDE se interpretan
> según RFC2119.

## 1. Generalidades
- **Transporte:** TCP. Escucha en un socket pasivo **distinto** al de SOCKS5
  (por defecto `127.0.0.1:8080`, configurable con `-L`/`-P`).
- **Formato:** texto, una unidad de protocolo por línea, terminada en `CRLF` (`\r\n`).
- **Codificación:** US-ASCII (7 bits).
- **Quién habla primero:** el **cliente** (tras conectar, inicia el handshake).
- **Concurrencia:** el servidor DEBE atenderlo de forma no bloqueante, multiplexado
  junto a SOCKS5 en el mismo hilo (máquina de estados propia).

## 2. Sintaxis general
```
comando   = palabra *( SP argumento ) CRLF
respuesta = ("+OK" [ SP texto ]) / ("-ERR" SP texto) CRLF
```
- Argumentos separados por **un** `SP` (0x20).
- `name` y `key`: `[A-Za-z0-9_-]{1,64}`.
- `pass` y `value`: imprimibles **sin espacios**, longitud máxima **255**.
- El servidor DEBE rechazar con `-ERR` toda línea que viole estos límites
  (longitud, caracteres, aridad) en lugar de comportamiento indefinido.
- Longitud máxima de línea: **512** bytes (incluye CRLF).

## 3. Handshake (obligatorio antes de cualquier comando)
```
C: HELLO <version>          ; ej. "HELLO 1"
S: +OK <version>            ; versión acordada
C: AUTH <admin-user> <admin-pass>
S: +OK                      ; autenticado
   ó
S: -ERR auth failed         ; el servidor DEBE cerrar la conexión
```
- Si la versión no es soportada: `S: -ERR unsupported version` y cierra.
- Antes de `AUTH` exitoso, el único comando aceptado es `HELLO`/`AUTH`;
  cualquier otro DEBE responder `-ERR not authenticated`.

## 4. Comandos (post-autenticación)

| Comando | Respuesta éxito | Errores típicos |
|---|---|---|
| `ADD-USER <name> <pass>` | `+OK` | `-ERR user exists`, `-ERR limit reached`, `-ERR bad name` |
| `DEL-USER <name>` | `+OK` | `-ERR no such user` |
| `LIST-USERS` | `+OK <N>` y luego `N` líneas `<name>` | — |
| `METRICS` | `+OK <N>` y luego `N` líneas `<key> <value>` | — |
| `GET-CONFIG <key>` | `+OK <value>` | `-ERR unknown key` |
| `SET-CONFIG <key> <value>` | `+OK` | `-ERR unknown key`, `-ERR bad value` |
| `QUIT` | `+OK bye` y cierra | — |

### Métricas mínimas (claves sugeridas)
`historic-connections`, `concurrent-connections`, `bytes-transferred`
(ampliar: `current-users`, `failed-connections`, …).

### Claves de configuración sugeridas
`buffer-size` (bytes de I/O por sentido), `log-level`. (Ampliable.)

## 5. Respuestas multi-línea (count-prefix)
Para `LIST-USERS` y `METRICS`, la primera línea es `+OK <N>` y le siguen
exactamente `N` líneas de datos. Esto permite al cliente saber cuántas leer
sin ambigüedad (alineado con el length-prefix que mostró el profe para GET).
```
C: METRICS
S: +OK 3
S: historic-connections 1422
S: concurrent-connections 87
S: bytes-transferred 9123847
```

## 6. Pipelining
El cliente PUEDE enviar varios comandos sin esperar cada respuesta; el servidor
DEBE responder **en el mismo orden** en que llegaron. (El profe lo recomendó
explícitamente: "es relativamente chiquito, está bueno que los protocolos lo
incluyan".)

## 7. Ejemplo de sesión completa
```
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
S: +OK 3
S: historic-connections 5
S: concurrent-connections 2
S: bytes-transferred 40960
C: QUIT
S: +OK bye
```

## 8. Consideraciones de implementación (no normativas)
- El cliente (`bin/client`) PUEDE usar I/O bloqueante; DEBE abstraer el protocolo
  en subcomandos cómodos (`client add-user pablito pass1234`) — **no** es netcat.
- El servidor parsea la línea con la máquina de estados / `parser` de la cátedra,
  respetando límites de tamaño para no cargar líneas arbitrariamente grandes.
