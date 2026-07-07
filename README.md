# TPE Protocolos de Comunicacion - Proxy SOCKS5

Servidor proxy SOCKS5 (RFC1928/RFC1929) en C11 con I/O no bloqueante
multiplexado, autenticacion usuario/contrasena, resolucion DNS para FQDN,
retry sobre multiples direcciones IP, metricas volatiles, access-log y un
Protocolo de Monitoreo y Configuracion (PMC) con cliente de terminal propio.

## Integrantes

- Keoni Dubovitsky
- Franco Ferrari
- Nicolas Mazzitelli
- Agustin Brunero

## Materiales de entrega

| Material | Ubicacion | Nota |
|---|---|---|
| Codigo fuente | `src/` | Servidor, cliente PMC y componentes compartidos. |
| Tests | `test/` | Unitarios C y scripts de integracion M1-M7. |
| Build | `Makefile`, `Makefile.inc` | Compilacion C11, targets de test, check y Valgrind. |
| Informe PDF | `docs/report/main.pdf` | Artefacto principal para entrega. |
| Fuentes del informe | `docs/report/main.tex`, `docs/report/sections/` | LaTeX reproducible. |
| RFC del PMC | `docs/mgmt-protocol-rfc.md` | Especificacion agnostica a implementacion. |
| Runner Pampero | `scripts/run-on-pampero.sh` | Sube el repo y corre gates Linux/Pampero. |
| Wrapper historico | `docs/run-on-pampero.sh` | Delega al runner oficial en `scripts/`. |
| Evidencia de stress | `docs/stress/2026-07-05_local-smoke_v1/` | CSV, figuras y `env.txt` versionables; logs operativos no son material de entrega. |
| Binarios generados | `bin/server`, `bin/client` | Se generan con `make`; no se versionan. |

## Compilacion

```bash
make clean && make
```

Por que usarlo: `make clean` elimina objetos/binarios viejos y evita demostrar
una build con artefactos de otra configuracion. `make` compila el servidor y el
cliente PMC con las flags de `Makefile.inc`.

Artefactos generados:

- `bin/server`: servidor SOCKS5 + listener PMC.
- `bin/client`: cliente CLI para el PMC.

## Ejecucion del servidor

```bash
./bin/server \
  -l 0.0.0.0 \
  -p 1080 \
  -L 127.0.0.1 \
  -P 8080 \
  -u user:pass \
  --admin admin:s3cr3t
```

Opciones relevantes:

| Opcion | Uso | Por que importa |
|---|---|---|
| `-l <addr>` | Direccion SOCKS5. Default `0.0.0.0`. | Define desde donde aceptan clientes SOCKS. |
| `-p <port>` | Puerto SOCKS5. Default `1080`. | Permite correr demos/tests sin chocar con servicios locales. |
| `-L <addr>` | Direccion PMC. Default `127.0.0.1`. | Mantiene el plano admin en loopback por defecto. |
| `-P <port>` | Puerto PMC. Default `8080`. | Se usa para cliente PMC, tests y stress. |
| `-u <name>:<pass>` | Usuario SOCKS5; hasta 10 por CLI. | Carga credenciales RFC1929 para el proxy. |
| `--admin <name>:<pass>` | Credencial de administracion PMC. | Usar un valor no-default en demo evita depender de `admin:s3cr3t`. |
| `-N` | Desactiva disectores. | Reduce trabajo extra si solo se quiere proxy/medicion base. |
| `-h` | Ayuda. | Debe terminar con codigo 0. |
| `-v` | Version. | Permite identificar build durante demo. |

## Cliente PMC

El cliente habla el handshake `HELLO` + `AUTH` y luego emite un comando PMC. No
es `netcat`; encapsula el protocolo de administracion en subcomandos.

```bash
./bin/client --admin admin:s3cr3t metrics
./bin/client --admin admin:s3cr3t add-user alice secret123
./bin/client --admin admin:s3cr3t del-user alice
./bin/client --admin admin:s3cr3t list-users
./bin/client --admin admin:s3cr3t get-config buffer-size
./bin/client --admin admin:s3cr3t set-config buffer-size 32768
./bin/client --admin admin:s3cr3t quit
```

Usar `-L <addr>` y `-P <port>` en el cliente si el PMC no esta en
`127.0.0.1:8080`.

## Verificacion local

```bash
make test
```

Por que usarlo: ejecuta los unitarios C puros para parsers, usuarios,
serializadores, metricas, logger, selector bloqueante y piezas de relay.

```bash
make check PORT=12080
```

Por que usarlo: corre `make test` y luego integracion M1-M7 contra sockets
reales. El puerto parametrizado evita colisiones con procesos locales.

```bash
make valgrind PORT=12080
```

Por que usarlo: en Linux/Pampero levanta el servidor bajo Valgrind y lo cruza
con trafico real. En macOS no reemplaza la evidencia Linux porque Valgrind no es
el entorno objetivo.

## Verificacion en Pampero

Runner oficial:

```bash
PAMPERO_USER=<usuario> bash scripts/run-on-pampero.sh 12080
```

El script sube el repo a `pampero.itba.edu.ar`, excluyendo `.git`, `obj/`,
`bin/` y `tmp/`, y ejecuta:

1. `make clean && make`
2. `make test`
3. `make check PORT=<puerto>`
4. `make valgrind PORT=<puerto+1>`

Salida esperada de una corrida valida: build OK, unitarios OK, integracion M1-M7
sin fallas y Valgrind con trafico sin errores ni leaks definitivos.

Evidencia disponible de Pampero/Linux:

- Entorno: `pampero.it.itba.edu.ar`, Linux `7.0.9-arch1-1`, GCC `16.1.1 20260625`.
- `make clean && make`: `BUILD OK`.
- Unitarios OK: `hello_test 21/0`, `auth_test 19/0`, `users_test 35/0`,
  `request_test 63/0`, `connect_test 23/0`, `copy_test 18/0`,
  `netutils_test 20/0`, `selector_block_test 17/0`, `metrics_test 16/0`,
  `logger_test 4/0`.
- Integracion: M1 `6 ok`, M2 `8 ok`, M3 `14 ok`, M4 `19 ok`, M5 `7 ok` con
  `1 skip` por retry multi-IP no aplicable en ese entorno, M6 access-log OK/FAIL,
  M7 `35 ok`.
- Valgrind + trafico: `ERROR SUMMARY: 0 errors from 0 contexts`,
  `definitely/indirectly/possibly lost: 0 bytes`, `2 fds` heredados al exit y
  `still reachable: 5,658 bytes` atribuible a libc/entorno.

## Stress

Script principal:

```bash
python3 test/stress/run_stress.py \
  --out-dir docs/stress/2026-07-05_local-smoke_v1 \
  --socks-port 11080 \
  --mgmt-port 12080 \
  --origin-port 18080 \
  --user user \
  --password pass \
  --admin root:toor \
  --concurrency 5,20 \
  --payload-bytes 1024,8192 \
  --target-modes ipv4,fqdn \
  --repeats 1
```

Graficos:

```bash
python3 test/stress/plot_stress.py \
  --in-dir docs/stress/2026-07-05_local-smoke_v1 \
  --formats png,svg
```

Que mide `run_stress.py`:

- concurrencia: cantidad de conexiones SOCKS simultaneas por caso;
- payload: bytes transferidos por conexion contra un origin controlado;
- target modes: destino `ipv4` o `fqdn`;
- metricas: conexiones OK/fallidas, bytes totales, wall time, throughput,
  tasa de conexiones, latencias p50/p95, REP no exitosos y deltas de metricas PMC.

Evidencia versionada:

- `2026-07-05_socks5-stress-summary_v1.csv`
- `2026-07-05_socks5-stress-connections_v1.csv`
- `2026-07-05_socks5-shutdown_v1.csv`
- figuras PNG/SVG de throughput, error rate y latencias;
- `env.txt` con host, OS, `FD_SETSIZE`, `ulimit -n` y `SC_OPEN_MAX`.

Lectura honesta de resultados:

- La evidencia versionada es un smoke local macOS con concurrencias 5 y 20,
  payloads 1024 y 8192 bytes, targets IPv4 y FQDN.
- Hubo una prueba local ad hoc separada de 500 conexiones con `conn_ok=500` y
  `conn_failed=0`.
- No se presenta un barrido completo de stress en Pampero; la evidencia Pampero
  fuerte es build, unitarios, integracion y Valgrind con trafico.

## Limitaciones conocidas

- El selector usa `pselect` y queda limitado por `FD_SETSIZE`; cada conexion
  proxy establecida consume fd cliente y fd origin.
- Las metricas son volatiles: se pierden al reiniciar el servidor.
- El PMC no usa TLS. Por default escucha en loopback (`127.0.0.1`); para demos
  usar `--admin` con credenciales no-default.
- El access-log es texto y debe recibir destinos sanitizados; el parser rechaza
  FQDN con controles ASCII para evitar inyeccion de lineas/campos.
