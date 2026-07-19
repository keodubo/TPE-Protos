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
| Tests | `test/` | Unitarios C e integraciones de SOCKS5, DNS, relay, metricas y PMC. |
| Build | `Makefile`, `Makefile.inc` | Compilacion C11, targets de test, check y Valgrind. |
| Informe PDF | `docs/report/main.pdf` | Artefacto principal para entrega. |
| Fuentes del informe | `docs/report/main.tex`, `docs/report/sections/` | LaTeX reproducible. |
| RFC del PMC | `docs/mgmt-protocol-rfc.md` | Especificacion agnostica a implementacion. |
| Runner Pampero | `scripts/run-on-pampero.sh` | Sube el repo y corre gates Linux/Pampero. |
| Wrapper historico | `docs/run-on-pampero.sh` | Delega al runner oficial en `scripts/`. |
| Evidencia de stress | `docs/stress/2026-07-05_local-smoke_v1/` | CSV, figuras y datos del entorno de la corrida local. |
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

El cliente negocia la version, autentica al administrador, traduce cada
subcomando al formato PMC y presenta la respuesta con etiquetas legibles.

```bash
./bin/client --admin admin:s3cr3t metrics
./bin/client --admin admin:s3cr3t add-user alice secret123
./bin/client --admin admin:s3cr3t del-user alice
./bin/client --admin admin:s3cr3t list-users
./bin/client --admin admin:s3cr3t get-config buffer-size
./bin/client --admin admin:s3cr3t set-config buffer-size 32768
```

Cada invocacion realiza una operacion y cierra su conexion. El comando PMC
`QUIT` queda reservado para clientes que mantengan una sesion persistente.

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

Por que usarlo: corre `make test` y luego prueba sobre sockets reales la
negociacion, autenticacion, conexion, relay, DNS, metricas y administracion. El
puerto parametrizado evita colisiones con procesos locales.

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

Salida esperada de una corrida valida: build y pruebas sin fallas, seguidas por
Valgrind con trafico real sin errores ni memoria perdida definitivamente.

Evidencia disponible de Pampero/Linux:

- Entorno: `pampero.it.itba.edu.ar`, Linux `7.0.9-arch1-1`, GCC `16.1.1 20260625`.
- `make clean && make`: `BUILD OK`.
- Los unitarios cubrieron parsers, usuarios, conexion, relay, selector, metricas
  y registro de accesos.
- Las integraciones ejercitaron el flujo SOCKS5 completo, resolucion DNS,
  reintentos, registro de accesos y operaciones PMC. El caso que requiere un
  dominio con varias direcciones se omitio porque el entorno no lo ofrecio.
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

- La evidencia versionada es una corrida local acotada en macOS con concurrencias 5 y 20,
  payloads 1024 y 8192 bytes, targets IPv4 y FQDN.
- Hubo una prueba local adicional de 500 conexiones con `conn_ok=500` y
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
