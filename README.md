# TPE Protocolos de Comunicación — Proxy SOCKS5

Servidor proxy **SOCKS5 (RFC1928)** en C11 con I/O no bloqueante multiplexado,
más un protocolo propio de monitoreo y configuración con su cliente de terminal.

> **Estado:** en desarrollo. Actualmente implementado **M0** (esqueleto echo no
> bloqueante que valida la integración del toolkit). Verificado compilando y
> corriendo en **pampero** (Arch Linux, gcc 16) y en **macOS**.

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
**M0 (estado actual):** el servidor acepta conexiones TCP en el puerto SOCKS y
hace *echo* de lo recibido (placeholder hasta implementar la negociación SOCKS5).

Prueba rápida del echo actual:
```bash
./bin/server -p 1080 &
printf 'hola\n' | nc 127.0.0.1 1080      # devuelve "hola"
kill %1
```

### Cliente de monitoreo
`./bin/client` — STUB por ahora (se implementa en M7, ver `docs/mgmt-protocol-rfc.md`).

## Créditos
Las utilidades de `src/shared/` (`selector`, `stm`, `buffer`, `parser`,
`parser_utils`, `netutils`) y `args` fueron provistas por la cátedra y se usan
con atribución, según lo permite la consigna.
