#include <argp.h>
#include <arpa/inet.h> /* inet_ntoa */
#include <asm-generic/socket.h>
#include <ifaddrs.h> /* getifaddrs() */
#include <linux/if.h> /* IFNAMSIZ */
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* malloc */
#include <string.h> /* memset */
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>

#include <libubus.h>
#include <libubox/blobmsg_json.h>

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
            {"interface", 'i', "INTERFACE", 0, "Network interface name", 0},
            {"source-addr", 'a', "ADDRESS", 0, "Source IP address", 0},
            {"source-port", 'p', "PORT", 0, "Source UDP port", 0},
            {"update-interval", 'u', "UPDATE_INTERVAL", 0, "Statistics update time", 1},
            {"ubus-socket", 's', "UBUS_SOCKET", 0, "ubus UNIX socket", 1},
            {0}
    };

/* Program configuration */
struct arguments
{
    char *interface_name;
    bool source_ip_set;
    struct in_addr source_ip;
    uint16_t source_port;
    uint64_t update_interval;
    const char *ubus_socket;
};

typedef struct {
    uint64_t packets;
    uint64_t bytes;
} statistics_t;

statistics_t statistics = {0};

pthread_mutex_t statistic_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_t ubus_event_thread;

void sigint_handler(int);
int check_interface_name(const char *);
void *ubus_event_thread_fn(void *);

/* SIGINT handler */
void sigint_handler(int signo __attribute__ ((unused))) {

	/* Print statistics */
    printf("\rTotal: packets = %lu, bytes = %lu\n", statistics.packets, statistics.bytes);

    /* Wait ubus thread to join */
    pthread_cancel(ubus_event_thread);
    pthread_join(ubus_event_thread, NULL);

    exit(EXIT_SUCCESS);
}

/* Print error message and exit */
static void perror_exit(const char *msg)
{
	perror(msg);
  	exit(EXIT_FAILURE);
}

/* Check input string for valid network interface name */
int check_interface_name(const char *interface_name)
{
    if (interface_name == NULL)
    {
        printf("Interface name is NULL\n");
        return(0);
    }

    if (strlen(interface_name) > IFNAMSIZ)
    {
    	printf("Interface name is too long\n");
        return(0);
    }

    /* Get network interfaces list */
    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1)
    	perror_exit("getifaddrs()");

    /* Cycle through to find name match*/
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_name != NULL &&
            strcmp(interface_name, ifa->ifa_name) == 0)
        {
        	/* matched */
            freeifaddrs(ifaddr);
            return(1);
        }
    }
    return(0);
}

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state)
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
            uint64_t interval = atoll(arg);
            if (interval < 1)
                argp_error(state, "Invalid update interval: %lu", interval);
            arguments->update_interval = interval;
        }
        break;
    case 's':
        {
            if (strlen(arg) < 1)
                argp_error(state, "Invalid UNIX socket: %s", arg);
            arguments->ubus_socket = arg;
        }
        break;
    default:
        return(ARGP_ERR_UNKNOWN);
    }
    return(0);
}

int main(int argc, char *argv[])
{
	/* Initializing arguments structure */
    struct arguments arguments =
    {
		.interface_name = NULL,
		.source_ip_set = false,
		.source_port = 0,
		.update_interval = 1000,
		.ubus_socket = NULL
    };

    /* Parsing command line arguments */
    struct argp argp = {options, parse_opt, NULL, doc, 0, 0, 0};
    if (argp_parse(&argp, argc, argv, 0, 0, &arguments))
    	perror_exit("argp_parse()");

    /* Block the SIGINT signal. The threads will inherit the signal mask.
	   This will avoid them catching SIGINT instead of this thread. */
	sigset_t sigset, oldset;
	if (sigemptyset(&sigset))
		perror_exit("sigemptyset()");
	if (sigaddset(&sigset, SIGINT))
		perror_exit("sigaddset()");
	if (pthread_sigmask(SIG_BLOCK, &sigset, &oldset))
		perror_exit("pthread_sigmask()");

	/* Spawn ubus event thread. */
	if (pthread_create(&ubus_event_thread, NULL, ubus_event_thread_fn, &arguments))
		perror_exit("pthread_create()");

	/* Install the signal handler for SIGINT. */
	struct sigaction s;
	s.sa_handler = sigint_handler;
	if (sigemptyset(&s.sa_mask))
		perror_exit("sigemptyset()");
	s.sa_flags = 0;
	if (sigaction(SIGINT, &s, NULL))
		perror_exit("sigaction()");

	/* Restore the old signal mask only for this thread. */
	if (pthread_sigmask(SIG_SETMASK, &oldset, NULL))
		perror_exit("pthread_sigmask()");

    printf("Starting...\n");

    /* Allocating buffer for received packet */
    uint8_t *buffer = (uint8_t *)malloc(BUFFER_SIZE);
    if (buffer == NULL)
    	perror_exit("malloc()");

    /* Open raw socket for UDP */
    int socket_raw = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socket_raw < 0)
    	perror_exit("socket()");
    else
        printf("socket(): Using SOCK_RAW socket and UDP protocol is OK.\n");

    /* Binding to network interface */
    if (arguments.interface_name != NULL)
    {
        if (setsockopt(socket_raw, SOL_SOCKET, SO_BINDTODEVICE,
                       arguments.interface_name, strlen(arguments.interface_name)))
        	perror_exit("setsockopt()");
        printf("setsockopt(): Binded to interface %s\n", arguments.interface_name);
    }

    /* Capturing packets */
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    ssize_t data_size = -1;
    while (1)
    {
    	/* Receive all UDP packets */
        data_size = recvfrom(socket_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (data_size < 0)
        	perror_exit("recvfrom()");

        /* Filter only matching packets */
        if ((arguments.source_ip_set && saddr.sin_addr.s_addr != arguments.source_ip.s_addr) ||
            (arguments.source_port && saddr.sin_port != arguments.source_port))
            continue;

        /* Update statistics */
        pthread_mutex_lock(&statistic_lock);
        ++statistics.packets;
        statistics.bytes += data_size;
        pthread_mutex_unlock(&statistic_lock);
    }

    return(EXIT_SUCCESS);
}

/* Thread to send ubus event with statistics */
void *ubus_event_thread_fn(void *p)
{
	struct ubus_context ctx;

	if (p == NULL)
		perror_exit("ubus_event_thread_fn(): arguments structure pointer is NULL");

	struct arguments *arg = (struct arguments *)p;

	/* Prepare timespec for nanosleep */
	struct timespec delay;
	delay.tv_sec = arg->update_interval / 1000;
	delay.tv_nsec = (arg->update_interval % 1000) * 1000;

	if (ubus_connect_ctx(&ctx, arg->ubus_socket))
		perror_exit("ubus_connect_ctx()");

	while (1)
	{
		static struct blob_buf b;
		blobmsg_buf_init(&b);

		/* Get statistics info */
		pthread_mutex_lock(&statistic_lock);
		blobmsg_add_u64(&b, "packets", statistics.packets);
		blobmsg_add_u64(&b, "bytes", statistics.bytes);
		pthread_mutex_unlock(&statistic_lock);

		/* Send ubus event*/
		ubus_send_event(&ctx, "statistics", b.head);

		/* Sleep */
		nanosleep(&delay, NULL);
	}

	return(NULL);
}

