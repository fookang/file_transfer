#include <sys/socket.h>
#define MAX_REQUEST_SIZE (1024 * 1024)

enum encoding_type
{
    none,
    length,
    chunked
};

struct client_info
{
    socklen_t address_length;
    struct sockaddr_storage address;
    char address_buffer[128];
    int socket;
    SSL *ssl;
    char request[MAX_REQUEST_SIZE + 1];
    int received; // number of bytes received in request
    struct client_info *next;
    int remaining_bytes;
    enum encoding_type encoding;
};

struct client_info *create_client_info(struct client_info **client_list)
{
    struct client_info *n = (struct client_info *)calloc(1, sizeof(struct client_info));

    n->address_length = sizeof(n->address);
    n->next = *client_list;
    n->remaining_bytes = 0;
    n->encoding = none;
    *client_list = n;

    return n;
}

int get_encoding_type(struct client_info *client)
{
    char *q = strstr(client->request, "Content-Length: ");
    if (q)
    {
        client->encoding = length;
        q = strchr(q, ' ');
        q += 1;
        client->remaining_bytes = strtol(q, 0, 10);
        return 1;
    }
    else
    {
        q = strstr(client->request, "Transfer-Encoding: chunked");
        if (q)
        {
            client->encoding = chunked;
            client->remaining_bytes = 0;
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}