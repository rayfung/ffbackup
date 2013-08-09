#ifndef FF_CONFIG_H
#define FF_CONFIG_H

#include <sys/types.h>
#include <limits.h>

class server_config
{
public:
    enum protocol{sslv3, tlsv1};

public:
    server_config();
    ~server_config();
    void reset();
    bool read_config(const char *path);
    int get_max_connection() const;
    const char *get_backup_root() const;
    enum protocol get_protocol() const;
    const char *get_host() const;
    const char *get_service() const;
    const char *get_ca_file() const;
    const char *get_cert_file() const;
    const char *get_key_file() const;
    const char *get_key_file_password() const;

private:
    const static size_t path_max = PATH_MAX;
    const static size_t host_max = 128;
    const static size_t service_max = 32;
    const static size_t passwd_max = 32;
    int max_connection;
    char backup_root[path_max];
    enum protocol protocol;
    char host[host_max];
    char service[service_max];
    char ca_file[path_max];
    char cert_file[path_max];
    char key_file[path_max];
    char key_file_passwd[passwd_max];
};

#endif
