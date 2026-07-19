#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mgmt_proto.h"

struct client_args {
    const char *host;
    const char *port;
    const char *admin_user;
    const char *admin_pass;
    int         cmd_argc;
    char      **cmd_argv;
};

enum client_command {
    CMD_ADD_USER,
    CMD_DEL_USER,
    CMD_LIST_USERS,
    CMD_METRICS,
    CMD_GET_CONFIG,
    CMD_SET_CONFIG,
};

static void
usage(const char *prog) {
    fprintf(stderr,
            "Uso: %s [-L host] [-P port] [--admin user:pass] <subcomando> [args]\n"
            "  add-user <name> <pass>\n"
            "  del-user <name>\n"
            "  list-users\n"
            "  metrics\n"
            "  get-config <key>\n"
            "  set-config <key> <value>\n",
            prog);
}

static int
parse_admin(char *value, struct client_args *args) {
    char *sep = strchr(value, ':');
    if (sep == NULL || sep == value || sep[1] == '\0') {
        return -1;
    }
    *sep = '\0';
    args->admin_user = value;
    args->admin_pass = sep + 1;
    return 0;
}

static int
parse_args(int argc, char **argv, struct client_args *args) {
    args->host = "127.0.0.1";
    args->port = "8080";
    args->admin_user = "admin";
    args->admin_pass = "s3cr3t";

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-L") == 0) {
            if (++i == argc) return -1;
            args->host = argv[i++];
        } else if (strcmp(argv[i], "-P") == 0) {
            if (++i == argc) return -1;
            args->port = argv[i++];
        } else if (strcmp(argv[i], "--admin") == 0) {
            if (++i == argc || parse_admin(argv[i], args) == -1) return -1;
            i++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            return 1;
        } else {
            break;
        }
    }

    args->cmd_argc = argc - i;
    args->cmd_argv = &argv[i];
    return args->cmd_argc > 0 ? 0 : -1;
}

static int
build_command(const struct client_args *args, char *line, const size_t cap,
              enum client_command *command) {
    const char *cmd = args->cmd_argv[0];
    int n = -1;

    if (strcmp(cmd, "add-user") == 0 && args->cmd_argc == 3) {
        n = snprintf(line, cap, "ADD-USER %s %s\r\n",
                     args->cmd_argv[1], args->cmd_argv[2]);
        *command = CMD_ADD_USER;
    } else if (strcmp(cmd, "del-user") == 0 && args->cmd_argc == 2) {
        n = snprintf(line, cap, "DEL-USER %s\r\n", args->cmd_argv[1]);
        *command = CMD_DEL_USER;
    } else if (strcmp(cmd, "list-users") == 0 && args->cmd_argc == 1) {
        n = snprintf(line, cap, "LIST-USERS\r\n");
        *command = CMD_LIST_USERS;
    } else if (strcmp(cmd, "metrics") == 0 && args->cmd_argc == 1) {
        n = snprintf(line, cap, "METRICS\r\n");
        *command = CMD_METRICS;
    } else if (strcmp(cmd, "get-config") == 0 && args->cmd_argc == 2) {
        n = snprintf(line, cap, "GET-CONFIG %s\r\n", args->cmd_argv[1]);
        *command = CMD_GET_CONFIG;
    } else if (strcmp(cmd, "set-config") == 0 && args->cmd_argc == 3) {
        n = snprintf(line, cap, "SET-CONFIG %s %s\r\n",
                     args->cmd_argv[1], args->cmd_argv[2]);
        *command = CMD_SET_CONFIG;
    } else {
        return -1;
    }

    return n >= 0 && (size_t) n < cap ? 0 : -1;
}

static int
reply_count(const struct mgmt_reply *reply, unsigned long *count) {
    char *end = NULL;
    errno = 0;
    const unsigned long parsed = strtoul(reply->text, &end, 10);
    if (errno != 0 || end == reply->text || *end != '\0') {
        fprintf(stderr, "client: cantidad multilinea PMC invalida\n");
        return -1;
    }
    *count = parsed;
    return 0;
}

static const char *
metric_label(const char *key) {
    if (strcmp(key, "historic-connections") == 0) return "Conexiones historicas";
    if (strcmp(key, "concurrent-connections") == 0) return "Conexiones concurrentes";
    if (strcmp(key, "bytes-transferred") == 0) return "Bytes transferidos";
    if (strcmp(key, "configured-users") == 0) return "Usuarios configurados";
    if (strcmp(key, "failed-connections") == 0) return "Conexiones fallidas";
    return key;
}

static int
print_multiline(const int fd, const struct mgmt_reply *reply,
                const enum client_command command) {
    unsigned long count = 0;
    if (reply_count(reply, &count) == -1) {
        return -1;
    }

    if (command == CMD_LIST_USERS) {
        printf("Usuarios (%lu):\n", count);
    } else {
        printf("Metricas:\n");
    }

    for (unsigned long i = 0; i < count; i++) {
        char line[MGMT_PROTO_LINE_MAX];
        if (mgmt_read_data_line(fd, line, sizeof(line)) == -1) {
            return -1;
        }
        if (command == CMD_LIST_USERS) {
            printf("- %s\n", line);
            continue;
        }

        char *value = strchr(line, ' ');
        if (value == NULL || value == line || value[1] == '\0') {
            fprintf(stderr, "client: metrica PMC invalida\n");
            return -1;
        }
        *value++ = '\0';
        printf("%s: %s\n", metric_label(line), value);
    }
    return 0;
}

static int
print_result(const struct client_args *args, const enum client_command command,
             const struct mgmt_reply *reply, const int fd) {
    switch (command) {
        case CMD_ADD_USER:
            printf("Usuario '%s' agregado.\n", args->cmd_argv[1]);
            return 0;
        case CMD_DEL_USER:
            printf("Usuario '%s' eliminado.\n", args->cmd_argv[1]);
            return 0;
        case CMD_LIST_USERS:
        case CMD_METRICS:
            return print_multiline(fd, reply, command);
        case CMD_GET_CONFIG:
            printf("%s: %s\n", args->cmd_argv[1], reply->text);
            return 0;
        case CMD_SET_CONFIG:
            printf("Configuracion '%s' actualizada a %s.\n",
                   args->cmd_argv[1], args->cmd_argv[2]);
            return 0;
    }
    return -1;
}

int
main(const int argc, char **argv) {
    struct client_args args;
    const int parsed = parse_args(argc, argv, &args);
    if (parsed != 0) {
        usage(argv[0]);
        return parsed > 0 ? 0 : 2;
    }

    char command[MGMT_PROTO_LINE_MAX];
    enum client_command command_kind;
    if (build_command(&args, command, sizeof(command), &command_kind) == -1) {
        usage(argv[0]);
        return 2;
    }

    int ret = 1;
    const int fd = mgmt_connect(args.host, args.port);
    if (fd == -1) {
        return 1;
    }

    struct mgmt_reply reply;
    const int handshake = mgmt_handshake(fd, args.admin_user, args.admin_pass,
                                         &reply);
    if (handshake != 0) {
        if (handshake > 0) {
            fprintf(stderr, "Error PMC: %s\n", reply.text);
        }
        goto done;
    }
    if (mgmt_send_line(fd, command) == -1) {
        perror("client: send");
        goto done;
    }

    const int status = mgmt_read_reply(fd, &reply);
    if (status > 0) {
        fprintf(stderr, "Error PMC: %s\n", reply.text);
        goto done;
    }
    if (status == -1 || print_result(&args, command_kind, &reply, fd) == -1) {
        goto done;
    }
    ret = 0;

done:
    close(fd);
    return ret;
}
