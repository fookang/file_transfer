#include <sys/stat.h>
#include <sys/types.h>

#define ITERATIONS 10000
#define SALT_LEN 16
#define FILE_PATH "users.txt"

struct user_info
{
    char username[32];
    unsigned char salt[SALT_LEN];
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    struct user_info *next;
};

int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || bytes_len < hex_len / 2)
        return 0;

    for (size_t i = 0; i < hex_len; i += 2)
    {
        unsigned int value;
        if (sscanf(&hex[i], "%2x", &value) != 1)
            return 0;
        bytes[i / 2] = (unsigned char)value;
    }
    return 1;
}

int load_users(const char *filename, struct user_info **users)
{
    FILE *file = fopen(filename, "r");
    if (!file)
        return 0;

    while (1)
    {
        struct user_info *user = calloc(1, sizeof(struct user_info));

        char salt_hex[SALT_LEN * 2 + 1] = {0};
        char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1] = {0};

        if (fscanf(file, "%31s %32s %64s", user->username, salt_hex, hash_hex) == 3)
        {
            if (!hex_to_bytes(salt_hex, user->salt, SALT_LEN) ||
                !hex_to_bytes(hash_hex, user->password_hash, SHA256_DIGEST_LENGTH))
            {
                free(user);
                continue;
            }
            user->next = *users;
            *users = user;
        }
        else
        {
            free(user);
            break;
        }
    }
    fclose(file);
    return 1;
}

int create_user(const char *username, const char *password, const char *filename, struct user_info **users)
{
    unsigned char salt[SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1)
    {
        fprintf(stderr, "Failed to generate salt.\n");
        return 0;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, sizeof(salt), ITERATIONS, EVP_sha256(), sizeof(hash), hash) != 1)
    {
        fprintf(stderr, "Failed to generate hash.\n");
        return 0;
    }

    struct user_info *user = *users;
    while (user)
    {
        if (user->username && strcmp(user->username, username) == 0)
        {
            return 0;
        }
        user = user->next;
    }

    FILE *file = fopen(filename, "a");
    if (file)
    {
        fprintf(file, "%s ", username);
        for (size_t i = 0; i < sizeof(salt); i++)
            fprintf(file, "%02x", salt[i]);
        fprintf(file, " ");
        for (size_t i = 0; i < sizeof(hash); i++)
            fprintf(file, "%02x", hash[i]);
        fprintf(file, "\n");
        fclose(file);
    }

    char path[256];
    if (snprintf(path, sizeof(path), "public/%s", username) < 0)
        return 0;

    if (mkdir(path, 0700) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "Failed to create directory %s\n", path);
        return 0;
    }

    const char *data_to_write =
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "  <title>Home</title>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>Welcome to the File Transfer Service</h1>\n"
        "</body>\n"
        "</html>\n";

    if (snprintf(path, sizeof(path), "public/%s/home.html", username) < 0)
    {
        fprintf(stderr, "Failed to create file path for %s\n", username);
        return 0;
    }

    file = fopen(path, "w");
    if (file)
    {
        fprintf(file, "%s", data_to_write);
        fclose(file);
    }
    else
    {
        return 0;
    }

    return 1;
}

void reload_users(const char *filename, struct user_info **users)
{
    struct user_info *current = *users;
    while (current)
    {
        struct user_info *next = current->next;
        free(current);
        current = next;
    }
    *users = NULL;

    if (!load_users(filename, users))
    {
        fprintf(stderr, "Failed to reload users.\n");
        exit(1);
    }
}

int verify_password(const char *password, const unsigned char *salt, const unsigned char *hash)
{
    unsigned char hash_check[SHA256_DIGEST_LENGTH];

    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_LEN, ITERATIONS, EVP_sha256(), SHA256_DIGEST_LENGTH, hash_check) != 1)
        return 0;

    return CRYPTO_memcmp(hash, hash_check, sizeof(hash_check)) == 0;
}

void free_users(struct user_info *users)
{
    struct user_info *current = users;
    while (current)
    {
        struct user_info *next = current->next;
        free(current);
        current = next;
    }
}