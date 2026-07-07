# TPE Protocolos de Comunicación — Proxy SOCKS5

Servidor proxy **SOCKS5 (RFC1928)** en C11 con I/O no bloqueante multiplexado,
más un protocolo propio de monitoreo y configuración con su cliente de terminal.

## Informe
El informe se encuentra [aquí](docs/report/main.pdf).

## Compilación
Requiere `gcc` (o `clang`) y `make`. Probado en **Linux** y **macOS**.
```bash
make            # compila server y client
make server     # solo el servidor -> bin/server
make client     # solo el cliente  -> bin/client
make clean      # borra obj/ y bin/
make check      # unitarios + integracion M1-M7
make valgrind   # Linux: leak/fd check con trafico real
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
./bin/server -p 1080 -u user:pass &
# handshake SOCKS5/auth/request con test/*_integration.sh o make check
kill %1
```
