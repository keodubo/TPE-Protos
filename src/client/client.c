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

static void
usage(const char *prog) {
    fprintf(stderr,
            "Uso: %s [-L host] [-P port] [--admin user:pass] <subcomando> [args]\n"
            "  add-user <name> <pass>\n"
            "  del-user <name>\n"
            "  list-users\n"
            "  metrics\n"
            "  get-config <key>\n"
            "  set-config <key> <value>\n"
            "  quit\n",
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
              int *multiline) {
    const char *cmd = args->cmd_argv[0];
    int n = -1;
    *multiline = 0;

    if (strcmp(cmd, "add-user") == 0 && args->cmd_argc == 3) {
        n = snprintf(line, cap, "ADD-USER %s %s\r\n",
                     args->cmd_argv[1], args->cmd_argv[2]);
    } else if (strcmp(cmd, "del-user") == 0 && args->cmd_argc == 2) {
        n = snprintf(line, cap, "DEL-USER %s\r\n", args->cmd_argv[1]);
    } else if (strcmp(cmd, "list-users") == 0 && args->cmd_argc == 1) {
        n = snprintf(line, cap, "LIST-USERS\r\n");
        *multiline = 1;
    } else if (strcmp(cmd, "metrics") == 0 && args->cmd_argc == 1) {
        n = snprintf(line, cap, "METRICS\r\n");
        *multiline = 1;
    } else if (strcmp(cmd, "get-config") == 0 && args->cmd_argc == 2) {
        n = snprintf(line, cap, "GET-CONFIG %s\r\n", args->cmd_argv[1]);
    } else if (strcmp(cmd, "set-config") == 0 && args->cmd_argc == 3) {
        n = snprintf(line, cap, "SET-CONFIG %s %s\r\n",
                     args->cmd_argv[1], args->cmd_argv[2]);
    } else if (strcmp(cmd, "quit") == 0 && args->cmd_argc == 1) {
        n = snprintf(line, cap, "QUIT\r\n");
    } else {
        return -1;
    }

    return n >= 0 && (size_t) n < cap ? 0 : -1;
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
    int multiline = 0;
    if (build_command(&args, command, sizeof(command), &multiline) == -1) {
        usage(argv[0]);
        return 2;
    }

    int ret = 1;
    const int fd = mgmt_connect(args.host, args.port);
    if (fd == -1) {
        return 1;
    }

    if (mgmt_handshake(fd, args.admin_user, args.admin_pass, stdout) == -1) {
        goto done;
    }
    if (mgmt_send_line(fd, command) == -1) {
        perror("client: send");
        goto done;
    }

    struct mgmt_reply reply;
    const int status = mgmt_read_reply(fd, &reply, stdout);
    if (status == 0 && multiline) {
        if (mgmt_expect_multiline(fd, &reply, stdout) == -1) {
            goto done;
        }
    }
    ret = status == 0 ? 0 : 1;

done:
    close(fd);
    return ret;
}
