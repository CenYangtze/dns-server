#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define DEFAULT_DNS_SERVER "202.106.0.20"
#define DEFAULT_TABLE_FILE "dnsrelay.txt"
#define DEFAULT_LISTEN_PORT 53
#define DNS_PORT 53
#define DNS_HEADER_SIZE 12
#define MAX_PACKET_SIZE 512
#define MAX_DOMAIN_LEN 255
#define MAX_TABLE_ENTRIES 8192
#define RELAY_TIMEOUT_SECONDS 10
#define LOCAL_TTL_SECONDS 60
#define DEFAULT_WORKER_THREADS 4
#define MAX_QUEUE_TASKS 4096

typedef struct {
    char domain[MAX_DOMAIN_LEN + 1];
    uint32_t ip_net;
    char ip_text[INET_ADDRSTRLEN];
} HostEntry;

typedef struct {
    int active;
    uint16_t original_id;
    struct sockaddr_in client_addr;
    int client_addr_len;
    time_t timestamp;
} PendingQuery;

typedef struct {
    int debug_level;
    unsigned short listen_port;
    int worker_threads;
    char upstream_ip[INET_ADDRSTRLEN];
    char table_file[MAX_PATH];
} Config;

typedef struct PacketTask {
    unsigned char packet[MAX_PACKET_SIZE];
    int packet_len;
    struct sockaddr_in from;
    int from_len;
    struct PacketTask *next;
} PacketTask;

typedef struct {
    PacketTask *head;
    PacketTask *tail;
    size_t size;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
} TaskQueue;

typedef struct {
    SOCKET sock;
    struct sockaddr_in upstream_addr;
    int debug_level;
    TaskQueue queue;
} ServerContext;

static HostEntry g_entries[MAX_TABLE_ENTRIES];
static size_t g_entry_count = 0;
static PendingQuery g_pending[65536];
static uint16_t g_next_relay_id = 1;
static unsigned long g_sequence = 0;
static pthread_mutex_t g_pending_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint16_t read_u16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_u16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)((value >> 8) & 0xff);
    p[1] = (unsigned char)(value & 0xff);
}

static void write_u32(unsigned char *p, uint32_t value) {
    p[0] = (unsigned char)((value >> 24) & 0xff);
    p[1] = (unsigned char)((value >> 16) & 0xff);
    p[2] = (unsigned char)((value >> 8) & 0xff);
    p[3] = (unsigned char)(value & 0xff);
}

static void normalize_domain(char *domain) {
    size_t len;

    for (char *p = domain; *p; ++p) {
        *p = (char)tolower((unsigned char)*p);
    }

    len = strlen(domain);
    while (len > 0 && domain[len - 1] == '.') {
        domain[len - 1] = '\0';
        --len;
    }
}

static int is_ipv4_literal(const char *text) {
    struct sockaddr_in addr;
    return InetPtonA(AF_INET, text, &addr.sin_addr) == 1;
}

static void print_usage(const char *program) {
    printf("Usage: %s [-d|-dd] [-p port] [-t workers] [dns-server-ipaddr] [filename]\n", program);
    printf("Default upstream DNS: %s\n", DEFAULT_DNS_SERVER);
    printf("Default table file: %s\n", DEFAULT_TABLE_FILE);
}

static int parse_args(int argc, char **argv, Config *config) {
    int positional_count = 0;

    config->debug_level = 0;
    config->listen_port = DEFAULT_LISTEN_PORT;
    config->worker_threads = DEFAULT_WORKER_THREADS;
    strcpy(config->upstream_ip, DEFAULT_DNS_SERVER);
    strcpy(config->table_file, DEFAULT_TABLE_FILE);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-d") == 0) {
            config->debug_level = 1;
        } else if (strcmp(argv[i], "-dd") == 0) {
            config->debug_level = 2;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            char *end = NULL;
            long port;

            if (i + 1 >= argc) {
                fprintf(stderr, "Missing port after %s\n", argv[i]);
                return 0;
            }
            port = strtol(argv[++i], &end, 10);
            if (*end != '\0' || port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", argv[i]);
                return 0;
            }
            config->listen_port = (unsigned short)port;
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            char *end = NULL;
            long threads;

            if (i + 1 >= argc) {
                fprintf(stderr, "Missing worker count after %s\n", argv[i]);
                return 0;
            }
            threads = strtol(argv[++i], &end, 10);
            if (*end != '\0' || threads <= 0 || threads > 64) {
                fprintf(stderr, "Invalid worker count: %s\n", argv[i]);
                return 0;
            }
            config->worker_threads = (int)threads;
        } else if (positional_count == 0 && is_ipv4_literal(argv[i])) {
            strncpy(config->upstream_ip, argv[i], sizeof(config->upstream_ip) - 1);
            config->upstream_ip[sizeof(config->upstream_ip) - 1] = '\0';
            positional_count++;
        } else if (positional_count <= 1) {
            strncpy(config->table_file, argv[i], sizeof(config->table_file) - 1);
            config->table_file[sizeof(config->table_file) - 1] = '\0';
            positional_count = 2;
        } else {
            fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
            return 0;
        }
    }

    return 1;
}

static void log_query(int level, int required, const char *fmt, ...) {
    va_list args;
    time_t now;
    struct tm local_time;
    char time_text[32];

    if (level < required) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);
    now = time(NULL);
    localtime_s(&local_time, &now);
    strftime(time_text, sizeof(time_text), "%H:%M:%S", &local_time);

    printf("[%s #%lu] ", time_text, ++g_sequence);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&g_log_mutex);
}

static int load_table(const char *filename) {
    FILE *file;
    char line[512];
    int line_no = 0;

    file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open table file %s: %s\n", filename, strerror(errno));
        return 0;
    }

    while (fgets(line, sizeof(line), file)) {
        char ip_text[64];
        char domain[MAX_DOMAIN_LEN + 1];
        struct sockaddr_in addr;

        line_no++;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        if (sscanf(line, "%63s %255s", ip_text, domain) != 2) {
            continue;
        }

        if (InetPtonA(AF_INET, ip_text, &addr.sin_addr) != 1) {
            fprintf(stderr, "Skip invalid IP at %s:%d: %s\n", filename, line_no, ip_text);
            continue;
        }

        if (g_entry_count >= MAX_TABLE_ENTRIES) {
            fprintf(stderr, "Too many table entries; max is %d\n", MAX_TABLE_ENTRIES);
            fclose(file);
            return 0;
        }

        normalize_domain(domain);
        strncpy(g_entries[g_entry_count].domain, domain, sizeof(g_entries[g_entry_count].domain) - 1);
        strncpy(g_entries[g_entry_count].ip_text, ip_text, sizeof(g_entries[g_entry_count].ip_text) - 1);
        g_entries[g_entry_count].ip_net = addr.sin_addr.S_un.S_addr;
        g_entry_count++;
    }

    fclose(file);
    return 1;
}

static const HostEntry *find_entry(const char *domain) {
    for (size_t i = 0; i < g_entry_count; ++i) {
        if (strcmp(g_entries[i].domain, domain) == 0) {
            return &g_entries[i];
        }
    }
    return NULL;
}

static int parse_qname(const unsigned char *packet, int packet_len, int offset, char *out, size_t out_size, int *qname_end) {
    int pos = offset;
    size_t out_len = 0;

    if (offset >= packet_len || out_size == 0) {
        return 0;
    }

    while (pos < packet_len) {
        unsigned char label_len = packet[pos++];

        if (label_len == 0) {
            if (out_len == 0) {
                if (out_size < 2) {
                    return 0;
                }
                out[out_len++] = '.';
            }
            out[out_len] = '\0';
            *qname_end = pos;
            normalize_domain(out);
            return 1;
        }

        if ((label_len & 0xc0) != 0 || label_len > 63) {
            return 0;
        }

        if (pos + label_len > packet_len || out_len + label_len + 1 >= out_size) {
            return 0;
        }

        if (out_len > 0) {
            out[out_len++] = '.';
        }
        memcpy(out + out_len, packet + pos, label_len);
        out_len += label_len;
        pos += label_len;
    }

    return 0;
}

static int get_question_info(const unsigned char *packet, int packet_len, char *domain, size_t domain_size, int *question_end, uint16_t *qtype, uint16_t *qclass) {
    int qname_end;

    if (packet_len < DNS_HEADER_SIZE || read_u16(packet + 4) == 0) {
        return 0;
    }

    if (!parse_qname(packet, packet_len, DNS_HEADER_SIZE, domain, domain_size, &qname_end)) {
        return 0;
    }

    if (qname_end + 4 > packet_len) {
        return 0;
    }

    *qtype = read_u16(packet + qname_end);
    *qclass = read_u16(packet + qname_end + 2);
    *question_end = qname_end + 4;
    return 1;
}

static int make_error_response(const unsigned char *query, int question_end, uint16_t rcode, unsigned char *response) {
    uint16_t req_flags;
    uint16_t flags;

    memcpy(response, query, question_end);
    req_flags = read_u16(query + 2);
    flags = (uint16_t)(0x8000 | (req_flags & 0x0100) | 0x0080 | (rcode & 0x000f));

    write_u16(response + 2, flags);
    write_u16(response + 4, 1);
    write_u16(response + 6, 0);
    write_u16(response + 8, 0);
    write_u16(response + 10, 0);
    return question_end;
}

static int make_a_response(const unsigned char *query, int question_end, uint32_t ip_net, unsigned char *response) {
    uint16_t req_flags;
    uint16_t flags;
    int pos = question_end;
    unsigned char *ip_bytes = (unsigned char *)&ip_net;

    if (question_end + 16 > MAX_PACKET_SIZE) {
        return 0;
    }

    memcpy(response, query, question_end);
    req_flags = read_u16(query + 2);
    flags = (uint16_t)(0x8000 | (req_flags & 0x0100) | 0x0080);

    write_u16(response + 2, flags);
    write_u16(response + 4, 1);
    write_u16(response + 6, 1);
    write_u16(response + 8, 0);
    write_u16(response + 10, 0);

    response[pos++] = 0xc0;
    response[pos++] = 0x0c;
    write_u16(response + pos, 1);
    pos += 2;
    write_u16(response + pos, 1);
    pos += 2;
    write_u32(response + pos, LOCAL_TTL_SECONDS);
    pos += 4;
    write_u16(response + pos, 4);
    pos += 2;
    memcpy(response + pos, ip_bytes, 4);
    pos += 4;

    return pos;
}

static void task_queue_init(TaskQueue *queue) {
    memset(queue, 0, sizeof(*queue));
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
}

static int task_queue_push(TaskQueue *queue, const unsigned char *packet, int packet_len, const struct sockaddr_in *from, int from_len) {
    PacketTask *task;

    if (packet_len <= 0 || packet_len > MAX_PACKET_SIZE) {
        return 0;
    }

    task = (PacketTask *)malloc(sizeof(*task));
    if (!task) {
        return 0;
    }

    memcpy(task->packet, packet, packet_len);
    task->packet_len = packet_len;
    task->from = *from;
    task->from_len = from_len;
    task->next = NULL;

    pthread_mutex_lock(&queue->mutex);
    if (queue->size >= MAX_QUEUE_TASKS) {
        pthread_mutex_unlock(&queue->mutex);
        free(task);
        return 0;
    }

    if (queue->tail) {
        queue->tail->next = task;
    } else {
        queue->head = task;
    }
    queue->tail = task;
    queue->size++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static PacketTask *task_queue_pop(TaskQueue *queue) {
    PacketTask *task;

    pthread_mutex_lock(&queue->mutex);
    while (queue->head == NULL) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    task = queue->head;
    queue->head = task->next;
    if (queue->head == NULL) {
        queue->tail = NULL;
    }
    queue->size--;
    pthread_mutex_unlock(&queue->mutex);

    task->next = NULL;
    return task;
}

static uint16_t allocate_relay_id_locked(void) {
    for (int i = 0; i < 65535; ++i) {
        uint16_t id = g_next_relay_id++;
        if (g_next_relay_id == 0) {
            g_next_relay_id = 1;
        }
        if (!g_pending[id].active) {
            return id;
        }
    }
    return 0;
}

static void cleanup_timeouts(int debug_level) {
    time_t now = time(NULL);

    pthread_mutex_lock(&g_pending_mutex);
    for (int i = 0; i < 65536; ++i) {
        if (g_pending[i].active && now - g_pending[i].timestamp > RELAY_TIMEOUT_SECONDS) {
            g_pending[i].active = 0;
            log_query(debug_level, 2, "timeout relay id=%d", i);
        }
    }
    pthread_mutex_unlock(&g_pending_mutex);
}

static int same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_family == b->sin_family &&
           a->sin_port == b->sin_port &&
           a->sin_addr.S_un.S_addr == b->sin_addr.S_un.S_addr;
}

static int handle_upstream_response(SOCKET sock, const unsigned char *packet, int packet_len, const struct sockaddr_in *from, const struct sockaddr_in *upstream, int debug_level) {
    uint16_t relay_id;
    PendingQuery *pending;
    uint16_t original_id;
    struct sockaddr_in client_addr;
    int client_addr_len;
    unsigned char response[MAX_PACKET_SIZE];

    if (!same_endpoint(from, upstream) || packet_len < DNS_HEADER_SIZE) {
        return 0;
    }

    relay_id = read_u16(packet);
    pthread_mutex_lock(&g_pending_mutex);
    pending = &g_pending[relay_id];
    if (!pending->active) {
        pthread_mutex_unlock(&g_pending_mutex);
        log_query(debug_level, 2, "drop unmatched upstream response id=%u", relay_id);
        return 1;
    }
    original_id = pending->original_id;
    client_addr = pending->client_addr;
    client_addr_len = pending->client_addr_len;
    pending->active = 0;
    pthread_mutex_unlock(&g_pending_mutex);

    memcpy(response, packet, packet_len);
    write_u16(response, original_id);

    sendto(sock, (const char *)response, packet_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
    log_query(debug_level, 1, "relay response id=%u original_id=%u", relay_id, original_id);
    return 1;
}

static void handle_client_query(SOCKET sock, const unsigned char *packet, int packet_len, const struct sockaddr_in *client_addr, int client_addr_len, const struct sockaddr_in *upstream, int debug_level) {
    char domain[MAX_DOMAIN_LEN + 1];
    int question_end = 0;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    uint16_t original_id;
    const HostEntry *entry;
    unsigned char response[MAX_PACKET_SIZE];
    int response_len;
    unsigned char forwarded[MAX_PACKET_SIZE];
    uint16_t relay_id;

    if (packet_len < DNS_HEADER_SIZE) {
        return;
    }

    if ((read_u16(packet + 2) & 0x8000) != 0) {
        return;
    }

    original_id = read_u16(packet);
    if (!get_question_info(packet, packet_len, domain, sizeof(domain), &question_end, &qtype, &qclass)) {
        response_len = make_error_response(packet, DNS_HEADER_SIZE, 1, response);
        sendto(sock, (const char *)response, response_len, 0, (const struct sockaddr *)client_addr, client_addr_len);
        return;
    }

    log_query(debug_level, 1, "query id=%u name=%s type=%u", original_id, domain, qtype);

    entry = find_entry(domain);
    if (entry && qclass == 1 && (qtype == 1 || qtype == 255)) {
        if (entry->ip_net == 0) {
            response_len = make_error_response(packet, question_end, 3, response);
            log_query(debug_level, 1, "blocked %s", domain);
        } else {
            response_len = make_a_response(packet, question_end, entry->ip_net, response);
            log_query(debug_level, 1, "local %s -> %s", domain, entry->ip_text);
        }
        sendto(sock, (const char *)response, response_len, 0, (const struct sockaddr *)client_addr, client_addr_len);
        return;
    }

    pthread_mutex_lock(&g_pending_mutex);
    relay_id = allocate_relay_id_locked();
    if (relay_id == 0) {
        pthread_mutex_unlock(&g_pending_mutex);
        response_len = make_error_response(packet, question_end, 2, response);
        sendto(sock, (const char *)response, response_len, 0, (const struct sockaddr *)client_addr, client_addr_len);
        return;
    }

    memcpy(forwarded, packet, packet_len);
    write_u16(forwarded, relay_id);
    g_pending[relay_id].active = 1;
    g_pending[relay_id].original_id = original_id;
    g_pending[relay_id].client_addr = *client_addr;
    g_pending[relay_id].client_addr_len = client_addr_len;
    g_pending[relay_id].timestamp = time(NULL);
    pthread_mutex_unlock(&g_pending_mutex);

    sendto(sock, (const char *)forwarded, packet_len, 0, (const struct sockaddr *)upstream, sizeof(*upstream));
    log_query(debug_level, 1, "forward %s original_id=%u relay_id=%u", domain, original_id, relay_id);
}

static void process_task(ServerContext *context, PacketTask *task) {
    if (!handle_upstream_response(context->sock, task->packet, task->packet_len, &task->from, &context->upstream_addr, context->debug_level)) {
        handle_client_query(context->sock, task->packet, task->packet_len, &task->from, task->from_len, &context->upstream_addr, context->debug_level);
    }
}

static void *worker_thread_main(void *arg) {
    ServerContext *context = (ServerContext *)arg;

    while (1) {
        PacketTask *task = task_queue_pop(&context->queue);
        process_task(context, task);
        free(task);
    }

    return NULL;
}

static void *timeout_thread_main(void *arg) {
    ServerContext *context = (ServerContext *)arg;

    while (1) {
        Sleep(1000);
        cleanup_timeouts(context->debug_level);
    }

    return NULL;
}

static int run_server(const Config *config) {
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in local_addr;
    struct sockaddr_in upstream_addr;
    ServerContext context;
    pthread_t timeout_thread;
    pthread_t *worker_threads = NULL;
    int result = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 0;
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        result = 0;
        goto cleanup;
    }

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(config->listen_port);

    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind port %u failed: %d\n", config->listen_port, WSAGetLastError());
        fprintf(stderr, "If using port 53 on Windows, run as administrator or test with -p 5353.\n");
        result = 0;
        goto cleanup;
    }

    memset(&upstream_addr, 0, sizeof(upstream_addr));
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(DNS_PORT);
    if (InetPtonA(AF_INET, config->upstream_ip, &upstream_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid upstream DNS IP: %s\n", config->upstream_ip);
        result = 0;
        goto cleanup;
    }

    memset(&context, 0, sizeof(context));
    context.sock = sock;
    context.upstream_addr = upstream_addr;
    context.debug_level = config->debug_level;
    task_queue_init(&context.queue);

    worker_threads = (pthread_t *)calloc((size_t)config->worker_threads, sizeof(*worker_threads));
    if (!worker_threads) {
        fprintf(stderr, "failed to allocate worker thread handles\n");
        result = 0;
        goto cleanup;
    }

    for (int i = 0; i < config->worker_threads; ++i) {
        if (pthread_create(&worker_threads[i], NULL, worker_thread_main, &context) != 0) {
            fprintf(stderr, "failed to create worker thread %d\n", i);
            result = 0;
            goto cleanup;
        }
    }

    if (pthread_create(&timeout_thread, NULL, timeout_thread_main, &context) != 0) {
        fprintf(stderr, "failed to create timeout thread\n");
        result = 0;
        goto cleanup;
    }

    printf("Threaded DNS relay started: listen=0.0.0.0:%u upstream=%s:%d table=%s entries=%zu workers=%d\n",
           config->listen_port, config->upstream_ip, DNS_PORT, config->table_file, g_entry_count, config->worker_threads);
    fflush(stdout);

    while (1) {
        unsigned char packet[MAX_PACKET_SIZE];
        struct sockaddr_in from;
        int from_len = sizeof(from);
        int packet_len;

        packet_len = recvfrom(sock, (char *)packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_len);
        if (packet_len == SOCKET_ERROR) {
            fprintf(stderr, "recvfrom failed: %d\n", WSAGetLastError());
            continue;
        }

        if (!task_queue_push(&context.queue, packet, packet_len, &from, from_len)) {
            log_query(config->debug_level, 1, "drop packet because task queue is full or allocation failed");
        }
    }

cleanup:
    if (worker_threads) {
        free(worker_threads);
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    WSACleanup();
    return result;
}

int main(int argc, char **argv) {
    Config config;

    if (!parse_args(argc, argv, &config)) {
        print_usage(argv[0]);
        return 1;
    }

    if (!load_table(config.table_file)) {
        return 1;
    }

    return run_server(&config) ? 0 : 1;
}
