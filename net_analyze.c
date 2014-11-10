#include <stdio.h>
#include <pcap.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <pthread.h>
#include <signal.h>
#include <time.h>

#include "uthash.h"

/* Network */
#define FILTER_IP "ip"
#define FILTER_HOST "ip host"

// Ethernet addresses are 6 bytes
#define ETHERNET_HEADER_LEN 14
#define ETHER_ADDR_LEN  6

// Ethernet header
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN];     /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN];     /* Source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

// IP header
struct sniff_ip
{
    u_char ip_vhl;          /* version << 4 | header length >> 2 */
    u_char ip_tos;          /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;          /* time to live */
    u_char ip_p;            /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/**/

/* Stats */
struct stat
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    struct timeval timestamp;
    long int bytes;
    long int pkts;
    UT_hash_handle hh;
};

struct stat *stats = NULL;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
int key_l = sizeof(struct in_addr) * 2;
/**/

/* PCAP */
pcap_t *handle = NULL;
#define END_CAPTURE do {pcap_breakloop(handle);} while(0);
/**/

/* Config */
FILE *stats_fd =NULL;
char *stats_path = NULL;
int print_stdout = 0;
#define DEFAULT_STATS_PATH "./stats.log"
#define DEFAULT_STORE_INTERVAL -1   // Seconds
/**/

void update_stats(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *
                  packet)
{
    struct sniff_ip *ip = (struct sniff_ip *)(packet + ETHERNET_HEADER_LEN);
    struct stat *target = NULL;

    if (pthread_mutex_lock(&stats_mutex) != 0)
    {
        fprintf(stderr, "Error locking statistics mutex\n");
        END_CAPTURE;
    }

    HASH_FIND(hh, stats, &ip->ip_src, key_l, target);
    if (target != NULL)             //If it is found, update stats
    {
        target->timestamp = pkthdr->ts;
        target->bytes += ntohs(ip->ip_len) +  ETHERNET_HEADER_LEN;
        target->pkts++;
    }
    else                            //If not, create entry and initialize stats
    {
        target = (struct stat *)malloc(sizeof(struct stat));
        target->ip_src = ip->ip_src;
        target->ip_dst = ip->ip_dst;
        target->timestamp = pkthdr->ts;
        target->bytes = ntohs(ip->ip_len) +  ETHERNET_HEADER_LEN;
        target->pkts = 1;

        HASH_ADD(hh, stats, ip_src, key_l, target);
    }

    if (pthread_mutex_unlock(&stats_mutex) != 0)
    {
        fprintf(stderr, "Error unlocking statistics mutex\n");
        END_CAPTURE;
    }
}

static void store_stats(void)
{
    struct stat *tmp = NULL, *target = NULL;
    struct tm *nowtm;
    char time_str[32], src[16], dst[16];

    if (pthread_mutex_lock(&stats_mutex) != 0)
    {
        fprintf(stderr, "Error locking statistics mutex\n");
        END_CAPTURE;
    }

    // Store stats
    HASH_ITER(hh, stats, target, tmp)
    {
        // Prepare time representation
        nowtm = localtime(&target->timestamp.tv_sec);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", nowtm);

        if (print_stdout)
        {
            printf("%s:\t %-15s  ->  %-15s  %12lu bytes %12lu frames\n",
                   time_str,
                   inet_ntop(AF_INET, &target->ip_src, src, sizeof(src)),
                   inet_ntop(AF_INET, &target->ip_dst, dst, sizeof(dst)),
                   target->bytes,
                   target->pkts);
        }

        fprintf(stats_fd, "%s:\t %-15s  ->  %-15s  %12lu bytes %12lu frames\n",
                time_str,
                inet_ntop(AF_INET, &target->ip_src, src, sizeof(src)),
                inet_ntop(AF_INET, &target->ip_dst, dst, sizeof(dst)),
                target->bytes,
                target->pkts);

        // Reset counter
        HASH_DEL(stats, target);
        free(target);
    }

    fflush(stats_fd);

    if (pthread_mutex_unlock(&stats_mutex) != 0)
    {
        fprintf(stderr, "Error unlocking statistics mutex\n");
        END_CAPTURE;
    }
}

static sig_atomic_t sigint = 1;
static void sighandler(int num)
{
    sigint = 0;
    END_CAPTURE;
}

void help(const char *program_name)
{
    printf( "Usage: %s [interface] [options]\n"
            "Supported options:\n"
            "       [-i | --ip]\t\tProcess only packets from or to this ip (it should be associated to the specified interface)\n"
            "       [-s | --stats_path]\tPath where to dump the statistics (default ./stats.log)\n"
            "       [-d | --duration]\tHow many seconds between dumps (default dump is done at exit)\n"
            "       [-p | --print]\t\tPrint to stdout\n"
            "       [-h | --help]\t\tShows this help message\n"
            , program_name);
}

static int get_args(int argc, char *const argv[], char **iface, char **ip, char **stats_path, unsigned *duration)
{
    int opt, option_index = 0, ret = 0;
    static struct option long_options[] =
    {
        {"help",            no_argument,            0,      'h'},
        {"ip",              required_argument,      0,      'i'},
        {"stats_path",      required_argument,      0,      's'},
        {"duration",        required_argument,      0,      'd'},
        {0, 0, 0, 0}
    };
    if (argc < 0)
    {
        ret = 1;
        goto end;
    }
    while ((opt = getopt_long(argc, argv, "hpi:s:d:", long_options, &option_index)))
    {
        switch (opt)
        {
        case 'h':
            help(argv[0]);
            exit(0);
        case 'i':
            *ip = strdup(optarg);
            break;
        case 's':
            *stats_path = strdup(optarg);
            break;
        case 'd':
            *duration = strtol(optarg, NULL, 10);
            break;
        case 'p':
            print_stdout = 1;
            break;
        case '?':           //Unexpected parameter
            help(argv[0]);
            exit(0);
        default:
            break;
        }
        if (opt == -1)
            break;
    }

    if (!*stats_path)
        *stats_path = (char *)DEFAULT_STATS_PATH;

    if (!*duration)
        *duration = DEFAULT_STORE_INTERVAL;

    if (argc < optind + 1)
    {
        fprintf(stderr, "No interface specified\n");
        help(argv[0]);
        exit(1);
    }
    else
    {
        *iface = strdup(argv[optind]);
    }

end:
    return ret;
}

int main(int argc, char *const argv[])
{
    int ret = 1, filter_exp_l = 0, err = 0, snaplen = 0;

    // Network
    char errbuf[PCAP_ERRBUF_SIZE];      /* Error string */
    struct bpf_program fp;              /* The compiled filter */
    char *filter_exp = NULL;            /* The filter expression */
    bpf_u_int32 mask;                   /* Our netmask */
    bpf_u_int32 net;                    /* Our IP */

    // To configure store stats thread timer
    struct itimerspec ts_stats;
    struct timespec interval_stats = {0}, first_stats = {0};
    timer_t stats_cleaner_timer = {0};
    struct sigevent sev_stats;

    // Config
    char *ip = NULL, *iface = NULL;
    unsigned duration = 0;

    if (get_args(argc, argv, &iface, &ip, &stats_path, &duration) != 0)
    {
        fprintf(stderr, "Error parsing arguments\n");
        goto end;
    }

    signal(SIGINT, sighandler);

    /* Open device */
    handle = pcap_create(iface, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        goto end;
    }
    /**/

    /* Find the properties for the device */
    if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get properties of device %s: %s\n", iface, errbuf);
        goto end;
    }
    /**/

    /* Open the session in promiscuous mode */
    snaplen = sizeof(struct sniff_ethernet) + sizeof(struct sniff_ip);
    handle = pcap_open_live(iface, snaplen, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        goto end;
    }
    /**/

    /* Compile and apply the filter */
    if (ip)
    {
        filter_exp_l = strlen(FILTER_HOST) + strlen(ip) + 2;
        filter_exp = (char *)malloc(filter_exp_l);
        snprintf(filter_exp, filter_exp_l, "%s %s", FILTER_HOST, ip);
    }
    else
    {
        filter_exp_l = strlen(FILTER_IP) + 1;
        filter_exp = (char *)malloc(strlen(FILTER_IP) + 1);
        snprintf(filter_exp, filter_exp_l, "%s", FILTER_IP);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        goto end;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        goto end;
    }
    /**/

    /* Create and prepare store stats thread */
    stats_fd = fopen(stats_path, "a+");

    interval_stats.tv_sec = duration;
    first_stats.tv_sec = duration;
    ts_stats.it_value = first_stats;
    ts_stats.it_interval = interval_stats;

    sev_stats.sigev_notify = SIGEV_THREAD;
    sev_stats.sigev_notify_function = (void *)store_stats;
    sev_stats.sigev_notify_attributes = NULL;

    if (timer_create(CLOCK_REALTIME, &sev_stats, &stats_cleaner_timer) == -1)
    {
        perror("Erorr creating store timer");
        goto end;
    }

    if (timer_settime(stats_cleaner_timer, 0, &ts_stats, NULL) == -1)
    {
        perror("Erorr setting store timer");
        goto end;
    }
    /**/

    while (sigint)
    {
        err = pcap_dispatch(handle, -1, update_stats, NULL);
        if (err == -1)
        {
            fprintf(stderr, "Something went wrong:a %s\n", pcap_geterr(handle));
            break;
        }
    }

    /* Store latest stats*/
    store_stats();
    /**/

end:
    fflush(stderr);
    fflush(stdout);

    if (filter_exp)
        free(filter_exp);

    //Free options
    if (ip)
        free(ip);
    if(iface)
        free(iface);
    if (stats_path != NULL && strcmp(stats_path, DEFAULT_STATS_PATH) != 0)
        free(stats_path);
    if (ip)
        free(ip);

    // Close pcap and stats file
    if (handle)
        pcap_close(handle);
    if (stats_fd)
        fclose(stats_fd);

    return ret;
}