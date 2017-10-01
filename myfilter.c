#include <argp.h>
#include <arpa/inet.h> // inet_ntoa
#include <asm-generic/socket.h>
#include <ifaddrs.h> // getifaddrs()
#include <linux/if.h> // IFNAMSIZ
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // memset
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

const char *argp_program_version =
        "myfilter 0.1";
const char *argp_program_bug_address =
        "<alexandergusarov@gmail.com>";

/* Program documentation. */
static char doc[] =
        "Simple UDP sniffer";

/* The options we understand. */
static struct argp_option options[] =
    {
            { "interface", 'i', "INTERFACE", 0, "Network interface name" },
            { "source-addr", 'a', "ADDRESS", 0, "Source IP address" },
            { "source-port", 'p', "PORT", 0, "Source UDP port" },
            { "update-interval", 'u', "UPDATE_INTERVAL", 0, "Statistics update time" },
            { 0 }
    };

typedef struct {
    uint64_t packets;
    uint64_t bytes;
} statistics_t;

statistics_t statistics = {0};

void intHandler(int);
int check_interface_name(const char *interface_name);

void intHandler(int dummy) {
    printf("\rTotal: packets = %lu, bytes = %lu\n", statistics.packets, statistics.bytes);
    exit(EXIT_SUCCESS);
}

int check_interface_name(const char *interface_name)
{
    if (interface_name == NULL)
    {
        perror("Interface name is NULL");
        return(0);
    }

    if (strlen(interface_name) > IFNAMSIZ)
    {
        perror("Interface name is too long");
        return(0);
    }

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs()");
        return(0);
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_name != NULL &&
            strcmp(interface_name, ifa->ifa_name) == 0)
        {
            freeifaddrs(ifaddr);
            return(1);
        }
    }
    return(0);
}

struct arguments
{
    char *interface_name;
    bool source_ip_set;
    struct in_addr source_ip;
    int source_port;
    int update_interval;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
    struct arguments *arguments = state->input;

    switch (key)
    {
    case 'i':
        {
            if(!check_interface_name(arg))
                argp_error(state, "No such interface: %s", arg);
            arguments->interface_name = arg;
        }
        break;
    case 'a':
        {
            if(!inet_aton(arg, &arguments->source_ip))
                argp_error(state, "Invalid source IP address: %s", arg);
            arguments->source_ip_set = true;
        }
        break;
    case 'p':
        {
            int port = atoi(arg);
            if (port < 1 || port > 65535)
                argp_error(state, "Invalid UDP port: %d", port);
            arguments->source_port = port;
        }
        break;
    case 'u':
        {
            int interval = atoi(arg);
            if (interval < 1)
                argp_error(state, "Invalid update interval: %d", interval);
            arguments->update_interval = interval;
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, NULL, doc };

int main(int argc, char *argv[])
{
    struct arguments arguments;
    arguments.interface_name = NULL;
    arguments.source_ip_set = false;
    arguments.source_port = 0;
    arguments.update_interval = 1000;

    argp_parse (&argp, argc, argv, 0, 0, &arguments);

    signal(SIGINT, intHandler);

    printf("Starting...\n");

    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);
    if (buffer == NULL)
    {
        perror("malloc()");
        return(EXIT_FAILURE);
    }

    int socket_raw = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_raw < 0)
    {
        perror("socket()");
        return(EXIT_FAILURE);
    }
    else
        printf("socket(): Using SOCK_RAW socket and UDP protocol is OK.\n");


    if (arguments.interface_name != NULL)
    {
        if (setsockopt(socket_raw, SOL_SOCKET, SO_BINDTODEVICE,
                       arguments.interface_name, strlen(arguments.interface_name)))
        {
            perror("setsockopt()");
            return(EXIT_FAILURE);
        }
        printf("setsockopt(): Binded to interface %s\n", arguments.interface_name);
    }

    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    ssize_t data_size = -1;
    while (1)
    {
        data_size = recvfrom(socket_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0)
        {
            perror("recvfrom()");
            return(EXIT_FAILURE);
        }

        if ((arguments.source_ip_set && saddr.sin_addr.s_addr != arguments.source_ip.s_addr) ||
            (arguments.source_port && saddr.sin_port != arguments.source_port))
            continue;
        ++statistics.packets;
        statistics.bytes += data_size;
    }

    close(socket_raw);
    printf("Finished\n");

    return(EXIT_SUCCESS);
}
