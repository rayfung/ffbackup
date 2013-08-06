#include <stdio.h>
#include "config.h"

server_config::server_config()
{
    this->max_connection = 256;
    this->backup_root[0] = '\0';
    this->protocol = server_config::sslv3;
    snprintf(this->host, host_max, "0.0.0.0");
    snprintf(this->service, service_max, "16903");
    snprintf(this->ca_file, path_max, "ca.crt");
    snprintf(this->cert_file, path_max, "server.crt");
    snprintf(this->key_file, path_max, "server.key");
    snprintf(this->key_file_passwd, passwd_max, "server");
}

int server_config::get_max_connection() const
{
    return this->max_connection;
}

const char *server_config::get_backup_root() const
{
    return this->backup_root;
}

enum server_config::protocol server_config::get_protocol() const
{
    return this->protocol;
}

const char *server_config::get_host() const
{
    return this->host;
}

const char *server_config::get_service() const
{
    return this->service;
}

const char *server_config::get_ca_file() const
{
    return this->ca_file;
}

const char *server_config::get_cert_file() const
{
    return this->cert_file;
}

const char *server_config::get_key_file() const
{
    return this->key_file;
}

const char *server_config::get_key_file_password() const
{
    return this->key_file_passwd;
}

server_config::~server_config()
{
}
