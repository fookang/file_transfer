#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "client_info.h"
#include "users.h"
#include "cookie.h"

#define PORTNO "8080"
#define BSIZE 1024

const char *get_content_type(const char *path)
{
    const char *last_dot = strrchr(path, '.');
    if (last_dot)
    {
        if (strcmp(last_dot, ".css") == 0)
            return "text/css";
        if (strcmp(last_dot, ".csv") == 0)
            return "text/csv";
        if (strcmp(last_dot, ".gif") == 0)
            return "image/gif";
        if (strcmp(last_dot, ".htm") == 0)
            return "text/html";
        if (strcmp(last_dot, ".html") == 0)
            return "text/html";
        if (strcmp(last_dot, ".ico") == 0)
            return "image/x-icon";
        if (strcmp(last_dot, ".jpeg") == 0)
            return "image/jpeg";
        if (strcmp(last_dot, ".jpg") == 0)
            return "image/jpeg";
        if (strcmp(last_dot, ".js") == 0)
            return "application/javascript";
        if (strcmp(last_dot, ".json") == 0)
            return "application/json";
        if (strcmp(last_dot, ".png") == 0)
            return "image/png";
        if (strcmp(last_dot, ".pdf") == 0)
            return "application/pdf";
        if (strcmp(last_dot, ".svg") == 0)
            return "image/svg+xml";
        if (strcmp(last_dot, ".txt") == 0)
            return "text/plain";
    }
    return "application/octet-stream";
}

int create_socket(const char *hostname, const char *port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    if (getaddrinfo(hostname, port, &hints, &bind_address))
    {
        fprintf(stderr, "getaddrinfo() failed (%d)\n", errno);
        exit(1);
    }

    int socket_listen;
    socket_listen = socket(bind_address->ai_family,
                           bind_address->ai_socktype,
                           bind_address->ai_protocol);

    if (socket_listen < 0)
    {
        fprintf(stderr, "socket() failed (%d)\n", errno);
        exit(1);
    }

    // Set socket to accept both ipv4 and ipv6
    int option = 0;
    if (setsockopt(socket_listen, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&option, sizeof(option)))
    {
        fprintf(stderr, "setsockopt() failed (%d)\n", errno);
        exit(1);
    }

    if (bind(socket_listen, bind_address->ai_addr,
             bind_address->ai_addrlen))
    {
        fprintf(stderr, "bind() failed (%d)\n", errno);
        exit(1);
    }

    freeaddrinfo(bind_address);

    printf("Listening...\n");
    if (listen(socket_listen, 10) < 0)
    {
        fprintf(stderr, "listen() failed. (%d)\n", errno);
        exit(1);
    }

    return socket_listen;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        exit(1);
    }

    return ctx;
}

void configure_conext(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file() failed.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

fd_set wait_on_client(const fd_set *master, const int max_socket)
{
    fd_set reads = *master;

    if (select(max_socket + 1, &reads, 0, 0, 0) < 0)
    {
        fprintf(stderr, "select() failed. (%d)\n", errno);
        exit(1);
    }

    return reads;
}

void drop_client(struct client_info **client_list, struct client_info *client, fd_set *master, int *max_socket, int server)
{
    int client_socket = client->socket;

    FD_CLR(client->socket, master);

    SSL_shutdown(client->ssl);
    close(client->socket);
    SSL_free(client->ssl);

    struct client_info **p = client_list;
    while (*p)
    {
        if (*p == client)
        {
            *p = client->next;
            free(client);
            break;
        }
        p = &(*p)->next;
    }

    if (*max_socket == client_socket)
    {
        struct client_info *ci = *client_list;
        int new_max = server;
        while (ci)
        {
            if (ci->socket > new_max)
                new_max = ci->socket;
            ci = ci->next;
        }
        *max_socket = new_max;
    }
}

const char *get_client_address(struct client_info *ci)
{
    getnameinfo((struct sockaddr *)&ci->address,
                ci->address_length,
                ci->address_buffer,
                sizeof(ci->address_buffer),
                0, 0,
                NI_NUMERICHOST);

    return ci->address_buffer;
}

void send_400(struct client_info **client_list, struct client_info *client, fd_set *master, int *max_socket, int server)
{
    const char *response =
        "HTTP/1.1 400 Bad Request\r\n"
        "Connection: close\r\n"
        "Content-Length: 11\r\n\r\n"
        "Bad Request";
    SSL_write(client->ssl, response, strlen(response));
    drop_client(client_list, client, master, max_socket, server);
}

void send_404(struct client_info **client_list, struct client_info *client, fd_set *master, int *max_socket, int server)
{
    const char *response =
        "HTTP/1.1 404 Not Found\r\n"
        "Connection: close\r\n"
        "Content-Length: 9\r\n\r\n"
        "Not Found";
    SSL_write(client->ssl, response, strlen(response));
    drop_client(client_list, client, master, max_socket, server);
}

void redirect(struct client_info **client_list, struct client_info *client, const char *location, fd_set *master, int *max_socket, int server)
{
    char buffer[BSIZE];
    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 302 Found\r\n"
             "Location: %s\r\n"
             "Connection: close\r\n"
             "Content-Length: 0\r\n\r\n",
             location);
    SSL_write(client->ssl, buffer, strlen(buffer));
    drop_client(client_list, client, master, max_socket, server);
}

void serve_resource(struct client_info **client_list, struct client_info *client, const char *path, fd_set *master, int *max_socket, int server)
{
    printf("serve_resource %s %s\n", get_client_address(client), path);

    if (strcmp(path, "/") == 0)
    {
        path = "/home.html";
    }

    if (strlen(path) > 100)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    if (strstr(path, ".."))
    {
        send_404(client_list, client, master, max_socket, server);
        return;
    }

    char full_path[128];
    snprintf(full_path, sizeof(full_path), "public%s", path);

    FILE *fp = fopen(full_path, "rb");
    if (!fp)
    {
        send_404(client_list, client, master, max_socket, server);
        return;
    }
    fseek(fp, 0L, SEEK_END);
    size_t cl = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    clearerr(fp);

    const char *content_type = get_content_type(full_path);

    char buffer[BSIZE];
    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 200 OK\r\n"
             "Connection: close\r\n"
             "Content-Length: %u\r\n"
             "Content-Type: %s\r\n\r\n",
             cl, content_type);
    SSL_write(client->ssl, buffer, strlen(buffer));

    int r = fread(buffer, 1, sizeof(buffer), fp);
    while (r)
    {
        SSL_write(client->ssl, buffer, r);
        r = fread(buffer, 1, sizeof(buffer), fp);
    }

    fclose(fp);
    drop_client(client_list, client, master, max_socket, server);
}

void send_with_cookie(struct client_info **client_list, struct client_info *client, const char *path, fd_set *master, int *max_socket, int server, const char *cookie_value)
{
    printf("serve_resource with cookie %s %s\n", get_client_address(client), path);

    if (strcmp(path, "/") == 0)
    {
        path = "/home.html";
    }

    if (strlen(path) > 100)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    if (strstr(path, ".."))
    {
        send_404(client_list, client, master, max_socket, server);
        return;
    }

    char full_path[128];
    snprintf(full_path, sizeof(full_path), "public%s", path);

    FILE *fp = fopen(full_path, "rb");
    if (!fp)
    {
        send_404(client_list, client, master, max_socket, server);
        return;
    }
    fseek(fp, 0L, SEEK_END);
    size_t cl = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    clearerr(fp);

    const char *content_type = get_content_type(full_path);

    char buffer[BSIZE];
    snprintf(buffer, sizeof(buffer),
             "HTTP/1.1 200 OK\r\n"
             "Connection: close\r\n"
             "Content-Length: %zu\r\n"
             "Content-Type: %s\r\n"
             "Set-Cookie: session=%s; HttpOnly; Secure; Path=/\r\n"
             "\r\n",
             cl, content_type, cookie_value);
    SSL_write(client->ssl, buffer, strlen(buffer));

    int r = fread(buffer, 1, sizeof(buffer), fp);
    while (r)
    {
        SSL_write(client->ssl, buffer, r);
        r = fread(buffer, 1, sizeof(buffer), fp);
    }

    fclose(fp);
    drop_client(client_list, client, master, max_socket, server);
}

int get_form_value(const char *body, const char *key, char *value, size_t value_size)
{
    char *key_pos = strstr(body, key);
    if (!key_pos)
        return 0;

    key_pos += strlen(key);
    if (*key_pos != '=')
        return 0;
    key_pos += 1;

    char *end_pos = strchr(key_pos, '&');
    if (!end_pos)
        end_pos = strchr(key_pos, '\0');

    size_t len = end_pos - key_pos;
    if (len >= value_size)
        len = value_size - 1;

    strncpy(value, key_pos, len);
    value[len] = 0;

    return 1;
}

int verify_login(const char *body, struct user_info *users)
{
    char username[64] = {0};
    char password[64] = {0};

    if (!get_form_value(body, "username", username, sizeof(username)))
        return 0;
    if (!get_form_value(body, "password", password, sizeof(password)))
        return 0;

    struct user_info *user = users;
    while (user)
    {
        if (strcmp(username, user->username) == 0)
        {
            if (verify_password(password, user->salt, user->password_hash))
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }
        user = user->next;
    }
    return 0;
}

int verify_register(const char *body, struct user_info **users)
{
    char username[64] = {0};
    char password[64] = {0};

    if (!get_form_value(body, "username", username, sizeof(username)))
        return 0;
    if (!get_form_value(body, "password", password, sizeof(password)))
        return 0;

    struct user_info *user = *users;
    while (user)
    {
        if (strcmp(username, user->username) == 0)
        {
            return 0;
        }
        user = user->next;
    }
    if (!create_user(username, password, FILE_PATH, users))
    {
        return 0;
    }
    reload_users(FILE_PATH, users);
    return 1;
}

enum PostDataStatus
{
    POST_DATA_INCOMPLETE,
    POST_DATA_COMPLETE
};

enum PostDataStatus wait_for_post_data(struct client_info *client, const char *body)
{
    if (client->encoding == length)
    {
        int body_length = client->received - (body - client->request);
        if (body_length < client->remaining_bytes)
        {
            return POST_DATA_INCOMPLETE;
        }

        return POST_DATA_COMPLETE;
    }

    else if (client->encoding == chunked)
    {
        if (!strstr(body, "\r\n0\r\n\r\n"))
        {
            return POST_DATA_INCOMPLETE;
        }

        do
        {
            if (client->remaining_bytes == 0)
            {
                if ((body = strstr(body, "\r\n")))
                {
                    client->remaining_bytes = strtol(body, 0, 16);
                    if (client->remaining_bytes == 0)
                        break;
                    body += 2;
                }
            }
            if (client->remaining_bytes)
            {
                // read chunk data

                body += client->remaining_bytes + 2;
                client->remaining_bytes = 0;
            }
        } while (!client->remaining_bytes);
        return POST_DATA_COMPLETE;
    }
    return POST_DATA_INCOMPLETE;
}

int parse_cookie_header(struct client_info *client, char *cookie_value, size_t value_size)
{
    char *cookie_header = strstr(client->request, "Cookie: ");
    if (!cookie_header)
    {
        fprintf(stderr, "No Cookie header found.\n");
        return 0;
    }

    char *session_start = strstr(cookie_header, "session=");
    if (!session_start)
    {
        fprintf(stderr, "No session header found.\n");
        return 0;
    }

    session_start += strlen("session=");

    char *session_end = strchr(session_start, ';');
    if (!session_end)
        session_end = strstr(session_start, "\r\n");
    if (!session_end)
    {
        fprintf(stderr, "No session end found.\n");
        return 0;
    }

    size_t len = session_end - session_start;
    if (len >= value_size)
        len = value_size - 1;

    strncpy(cookie_value, session_start, len);
    cookie_value[len] = '\0';

    return 1;
}

void handle_post_login(struct client_info **client_list, struct client_info *client, const char *body, fd_set *master, int *max_socket, int server, struct user_info **users, struct cookie **cookies)
{
    if (client->encoding == none)
    {
        if (!get_encoding_type(client))
        {
            send_400(client_list, client, master, max_socket, server);
            return;
        }
    }

    if (strncmp(client->request, "POST /login", 11) == 0)
    {

        enum PostDataStatus status = wait_for_post_data(client, body);
        if (status == POST_DATA_INCOMPLETE)
        {
            return;
        }
        else if (status == POST_DATA_COMPLETE)
        {

            if (!verify_login(body, *users))
            {
                serve_resource(client_list, client, "/login_fail.html", master, max_socket, server);
                return;
            }

            char username[64] = {0};
            char cookie_value[COOKIE_LEN + 1] = {0};
            get_form_value(body, "username", username, sizeof(username));

            create_cookie(COOKIE_FILE_PATH, username, cookie_value, sizeof(cookie_value));
            reload_cookies(COOKIE_FILE_PATH, cookies);

            char path_with_user[128];
            snprintf(path_with_user, sizeof(path_with_user), "/%s/home.html", username);
            send_with_cookie(client_list, client, path_with_user, master, max_socket, server, cookie_value);
        }
    }
}

void handle_register(struct client_info **client_list, struct client_info *client, const char *body, fd_set *master, int *max_socket, int server, struct user_info **users)
{
    if (client->encoding == none)
    {
        if (!get_encoding_type(client))
        {
            send_400(client_list, client, master, max_socket, server);
            return;
        }
    }

    if (strncmp(client->request, "POST /register", 14) == 0)
    {

        enum PostDataStatus status = wait_for_post_data(client, body);
        if (status == POST_DATA_INCOMPLETE)
        {
            return;
        }
        else if (status == POST_DATA_COMPLETE)
        {
            if (!verify_register(body, users))
            {
                serve_resource(client_list, client, "/register_fail.html", master, max_socket, server);
                return;
            }
            serve_resource(client_list, client, "/register_success.html", master, max_socket, server);
        }
    }
}

void print_http_request(const char *request)
{
    printf("----- HTTP Request Start -----\n");
    printf("%s", request);
    printf("----- HTTP Request End -----\n");
}

void handle_upload(struct client_info **client_list, struct client_info *client, const char *body, fd_set *master, int *max_socket, int server)
{
    char cookie_value[COOKIE_LEN + 1] = {0};
    if (!parse_cookie_header(client, cookie_value, COOKIE_LEN + 1))
    {
        fprintf(stderr, "Failed to parse cookie header.\n");
        redirect(client_list, client, "/login", master, max_socket, server);
        return;
    }

    const char *username = verify_cookie(cookie_value, NULL);
    if (!username)
    {
        fprintf(stderr, "Invalid cookie.\n");
        redirect(client_list, client, "/login", master, max_socket, server);
        return;
    }

    if (strstr(client->request, "\r\nExpect: 100-continue\r\n"))
    {
        {
            const char *cont = "HTTP/1.1 100 Continue\r\n\r\n";
            SSL_write(client->ssl, cont, strlen(cont));
        }
    }

    if (client->encoding == none)
    {
        if (!get_encoding_type(client))
        {
            send_400(client_list, client, master, max_socket, server);
            return;
        }
    }

    if (client->encoding != length)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    const long length = client->remaining_bytes;

    long already_received = client->received - (long)(body - client->request);
    if (already_received < 0)
        already_received = 0;
    if (already_received > length)
        already_received = length;

    char directory[128];
    if (snprintf(directory, sizeof(directory), "public/%s/uploads", username) < 0)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    if (mkdir(directory, 0700) < 0 && errno != EEXIST)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    FILE *file = fopen(directory, "wb");
    if (!file)
    {
        send_400(client_list, client, master, max_socket, server);
        return;
    }

    if (already_received > 0)
    {
        fwrite(body, 1, already_received, file);
    }

    long written = already_received;
    char buffer[4096];

    while (written < length)
    {
        
    }

    const char *response =
        "HTTP/1.1 501 Not Implemented\r\n"
        "Connection: close\r\n"
        "Content-Length: 15\r\n\r\n"
        "Not Implemented";
    SSL_write(client->ssl, response, strlen(response));

    drop_client(client_list, client, master, max_socket, server);
}

int main()
{
    SSL_CTX *ctx = create_context();
    configure_conext(ctx);

    int server = create_socket(0, PORTNO);

    struct client_info *client_list = 0;
    fd_set master;
    FD_ZERO(&master);
    FD_SET(server, &master);
    int max_socket = server;

    struct user_info *users = 0;
    if (!load_users(FILE_PATH, &users))
    {
        fprintf(stderr, "Failed to load users.\n");
        return 1;
    }

    struct cookie *cookies = 0;
    if (!load_cookies(COOKIE_FILE_PATH, &cookies))
    {
        fprintf(stderr, "Failed to load cookies.\n");
        return 1;
    }

    while (1)
    {
        fd_set reads = wait_on_client(&master, max_socket);

        if (FD_ISSET(server, &reads))
        {
            struct client_info *ci = create_client_info(&client_list);
            ci->socket = accept(server, (struct sockaddr *)&ci->address, &ci->address_length);

            if (ci->socket < 0)
            {
                fprintf(stderr, "accept() failed. (%d)\n", errno);

                struct client_info **tmp = &client_list;
                if (*tmp == ci)
                {
                    *tmp = ci->next;
                    free(ci);
                }
                continue;
            }

            ci->ssl = SSL_new(ctx);

            if (!ci->ssl)
            {
                fprintf(stderr, "SSL_new() failed.\n");
                close(ci->socket);
                struct client_info **tmp = &client_list;
                if (*tmp == ci)
                {
                    *tmp = ci->next;
                    free(ci);
                }
                continue;
            }

            SSL_set_fd(ci->ssl, ci->socket);
            if (SSL_accept(ci->ssl) <= 0)
            {
                fprintf(stderr, "SSL_accept() failed.\n");
                ERR_print_errors_fp(stderr);

                close(ci->socket);
                SSL_free(ci->ssl);
                struct client_info **tmp = &client_list;
                if (*tmp == ci)
                {
                    *tmp = ci->next;
                    free(ci);
                }
                continue;
            }
            else
            {
                printf("SSL connection established with %s.\n", get_client_address(ci));
            }

            FD_SET(ci->socket, &master);
            if (ci->socket > max_socket)
                max_socket = ci->socket;
        }

        struct client_info *client = client_list;

        while (client)
        {
            struct client_info *next = client->next;
            if (FD_ISSET(client->socket, &reads))
            {
                char *head_end = strstr(client->request, "\r\n\r\n");

                if (!head_end)
                {
                    if (client->received >= MAX_REQUEST_SIZE)
                    {
                        send_400(&client_list, client, &master, &max_socket, server);
                        client = next;
                        continue;
                    }
                    int byte_recevied = SSL_read(client->ssl,
                                                 client->request + client->received,
                                                 sizeof(client->request) - client->received - 1);

                    if (byte_recevied < 1)
                    {
                        printf("Unexpected disconnect from %s.\n", get_client_address(client));

                        drop_client(&client_list, client, &master, &max_socket, server);
                        client = next;
                        continue;
                    }

                    client->received += byte_recevied;
                    client->request[client->received] = 0;

                    if (!head_end)
                    {
                        client = next;
                        continue;
                    }
                }

                char *body = head_end + 4;

                if (strncmp(client->request, "POST ", 5) == 0)
                {
                    if (strncmp(client->request + 5, "/login ", 7) == 0)
                    {
                        handle_post_login(&client_list, client, body, &master, &max_socket, server, &users, &cookies);
                    }
                    else if (strncmp(client->request + 5, "/register ", 9) == 0)
                    {
                        handle_register(&client_list, client, body, &master, &max_socket, server, &users);
                    }
                    else if (strncmp(client->request + 5, "/upload ", 8) == 0)
                    {
                        handle_upload(&client_list, client, body, &master, &max_socket, server);
                    }
                    else
                    {
                        send_400(&client_list, client, &master, &max_socket, server);
                    }
                    client = next;
                    continue;
                }

                else if (strncmp(client->request, "GET ", 4) == 0)
                {

                    char *path = client->request + 4;
                    char *end_path = strchr(path, ' ');
                    if (!end_path)
                    {
                        send_400(&client_list, client, &master, &max_socket, server);
                        client = next;
                        continue;
                    }

                    size_t path_len = end_path - path;
                    if (path_len >= 100)
                    {
                        send_400(&client_list, client, &master, &max_socket, server);
                        client = next;
                        continue;
                    }

                    char path_buffer[100];
                    strncpy(path_buffer, path, path_len);
                    path_buffer[path_len] = 0;
                    path = path_buffer;

                    if (strcmp(path, "/login") == 0)
                    {
                        serve_resource(&client_list, client, "/login.html", &master, &max_socket, server);
                    }
                    else if (strcmp(path, "/register") == 0)
                    {
                        serve_resource(&client_list, client, "/register.html", &master, &max_socket, server);
                    }
                    else
                    {
                        char cookie_value[COOKIE_LEN + 1];

                        if (parse_cookie_header(client, cookie_value, COOKIE_LEN + 1))
                        {
                            char *username = verify_cookie(cookie_value, cookies);

                            if (!username)
                            {
                                fprintf(stderr, "Invalid cookie value: %s\n", cookie_value);
                                redirect(&client_list, client, "/login", &master, &max_socket, server);
                                client = next;
                                continue;
                            }

                            const char *actual_path = path;
                            if (strcmp(actual_path, "/") == 0)
                                actual_path = "/home.html";

                            char path_with_user[128];

                            snprintf(path_with_user, sizeof(path_with_user), "/%s%s", username, actual_path);

                            serve_resource(&client_list, client, path_with_user, &master, &max_socket, server);
                        }
                        else
                        {
                            redirect(&client_list, client, "/login", &master, &max_socket, server);
                            client = next;
                            continue;
                        }
                    }

                    client = next;
                    continue;
                }

                else
                {
                    send_400(&client_list, client, &master, &max_socket, server);
                }
            }
            client = next;
        }
    }

    free_users(users);
    free_cookies(cookies);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
