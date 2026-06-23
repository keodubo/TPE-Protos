# TPE Protocolos de Comunicación — Proxy SOCKS5

Servidor proxy **SOCKS5 (RFC1928)** en C11 con I/O no bloqueante multiplexado,
más un protocolo propio de monitoreo y configuración con su cliente de terminal.

> **Estado:** en desarrollo. Actualmente implementados **M1/M2/M3 estricto**:
> HELLO SOCKS5, autenticacion user/pass y REQUEST + CONNECT IPv4 literal no
> bloqueante. El relay de datos queda para **M4**. Verificado compilando y
> corriendo en **pampero** (Arch Linux, gcc 16) y en **macOS**.

## Estado de hitos y QA

- **M1:** negociacion HELLO SOCKS5.
- **M2:** autenticacion user/pass (RFC1929).
- **M3:** REQUEST + CONNECT solo para `CMD=CONNECT` y `ATYP=IPv4`; FQDN/IPv6 y
  comandos no soportados responden con REP de error.
- **M4 pendiente:** relay/copy de datos entre cliente y origen.

Regla de mantenimiento: cada implementacion de un nuevo **M** debe actualizar o
agregar sus tests unitarios e integracion correspondientes, y revisar si los
tests de los hitos anteriores siguen describiendo el comportamiento actual. El
objetivo es que `make check` cubra la regresion M1/M2/M3 y no quede una suite
verde pero obsoleta. Para paths de memoria/fds bajo trafico real, usar
`make valgrind` en Linux/pampero.

## Estructura del repositorio
```
.
├── Makefile, Makefile.inc        # build (genera bin/server y bin/client)
├── README.md                     # este archivo
├── docs/
│   ├── mgmt-protocol-rfc.md          # RFC (borrador) del protocolo de monitoreo
│   └── pampero-runner.example.sh     # plantilla para probar en pampero (copiar y editar)
├── src/
│   ├── server/                   # servidor SOCKS5 (main.c, máquina de estados, ...)
│   ├── client/                   # cliente del protocolo de monitoreo
│   └── shared/                   # toolkit de la cátedra + args (selector, stm, buffer, parser, netutils)
├── test/                         # tests de las utilidades (provistos por la cátedra)
└── tmp/                          # material de la cátedra (NO versionado: ver .gitignore)
```

## Compilación
Requiere `gcc` (o `clang`) y `make`. Probado en **Linux** (pampero) y **macOS**.
```bash
make            # compila server y client
make server     # solo el servidor -> bin/server
make client     # solo el cliente  -> bin/client
make clean      # borra obj/ y bin/
```
Los binarios quedan en `bin/`.

## Ejecución
### Servidor
```bash
./bin/server [OPCIONES]
  -l <addr>        dirección donde sirve el proxy SOCKS   (default 0.0.0.0)
  -p <port>        puerto SOCKS                            (default 1080)
  -L <addr>        dirección del servicio de management    (default 127.0.0.1)
  -P <port>        puerto de management                    (default 8080)
  -u <name>:<pass> usuario del proxy (hasta 10)
  -N               desactiva los disectores (sniffing)
  -h / -v          ayuda / versión
```
Prueba rapida del servidor SOCKS:
```bash
./bin/server -p 1080 &
# handshake SOCKS5/auth/request con test/*_integration.sh o make check
kill %1
```

### Cliente de monitoreo
`./bin/client` — STUB por ahora (se implementa en M7, ver `docs/mgmt-protocol-rfc.md`).

## Créditos
Las utilidades de `src/shared/` (`selector`, `stm`, `buffer`, `parser`,
`parser_utils`, `netutils`) y `args` fueron provistas por la cátedra y se usan
con atribución, según lo permite la consigna.
