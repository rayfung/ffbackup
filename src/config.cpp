#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "ffbuffer.h"

server_config::server_config()
{
    this->reset();
}

void server_config::reset()
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

/**
 *
 * 从配置文件中读取配置
 *
 * @param path 配置文件完整路径
 * @return 如果成功则返回true，否则返回false，此时的配置状态未定义
 *
 */
bool server_config::read_config(const char *path)
{
    char buffer[1024];
    int fd;
    ssize_t ret;
    ffbuffer content;
    size_t line_num;

    fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        perror("open");
        return false;
    }
    while((ret = read(fd, buffer, sizeof(buffer))) > 0)
        content.push_back(buffer, ret);
    close(fd);

    line_num = 1;
    while(content.get_size() > 0)
    {
        size_t key_len;
        size_t value_len;
        size_t extra;
        size_t i;
        char key[32];
        bool found;
        const char *key_list[] = {
            "backup_root", "bind_host", "bind_service",
            "ca_file", "cert_file", "key_file",
            "key_file_passwd"
        };
        char *value_list[] = {
            this->backup_root, this->host, this->service,
            this->ca_file, this->cert_file, this->key_file,
            this->key_file_passwd
        };
        size_t size_list[] = {
            path_max, host_max, service_max,
            path_max, path_max, path_max,
            passwd_max
        };
        size_t item_count = 7;

        key_len = content.find('\x20', &found);
        if(found && key_len <= sizeof(key))
        {
            content.get(key, 0, key_len);
            content.pop_front(key_len);

            for(i = 0; i < content.get_size(); ++i)
            {
                unsigned char ch;
                ch = content.at(i);
                if(ch != '\x20' && ch != '\t')
                    break;
            }
            content.pop_front(i);

            value_len = content.find('\n', &found);
            if(found)
                extra = 1;
            else
                extra = 0;

            for(i = 0; i < item_count; ++i)
            {
                if(strncmp(key, key_list[i], key_len) == 0)
                {
                    if(value_len >= size_list[i])
                    {
                        fprintf(stderr, "read_config: %s too long(line %d)\n",
                                key_list[i], (int)line_num);
                        return false;
                    }
                    content.get(value_list[i], 0, value_len);
                    value_list[i][value_len] = '\0';
                    fprintf(stderr, "%s=%s\n", key_list[i], value_list[i]);
                    break;
                }
            }
            if(i < item_count)
                ;
            else if(strncmp(key, "max_connection", key_len) == 0)
            {
                char max_conn[16];
                if(value_len >= sizeof(max_conn))
                {
                    fprintf(stderr, "read_config: max_connection too long(line %d)\n",
                            (int)line_num);
                    return false;
                }
                content.get(max_conn, 0, value_len);
                max_conn[value_len] = '\0';
                this->max_connection = atoi(max_conn);
                if(this->max_connection < 8)
                    this->max_connection = 8;
                if(this->max_connection > 1024)
                    this->max_connection = 1024;
                fprintf(stderr, "max_connection=%d\n", this->max_connection);
            }
            else if(strncmp(key, "protocol", key_len) == 0)
            {
                char protocol[16];
                if(value_len >= sizeof(protocol))
                {
                    fprintf(stderr, "read_config: protocol too long(line %d)\n",
                            (int)line_num);
                    return false;
                }
                content.get(protocol, 0, value_len);
                protocol[value_len] = '\0';
                if(strcmp(protocol, "sslv3") == 0)
                    this->protocol = sslv3;
                else if(strcmp(protocol, "tlsv1") == 0)
                    this->protocol = tlsv1;
                else
                {
                    fprintf(stderr, "read_config: protocol not supported(line %d)\n",
                            (int)line_num);
                    return false;
                }
                fprintf(stderr, "protocol=%s\n", protocol);
            }
            else
            {
                fprintf(stderr, "read_config: key invalid (line %d)\n", (int)line_num);
                return false;
            }
            content.pop_front(value_len + extra);
        }
        else
        {
            fprintf(stderr, "read_config: key is too long (line %d)\n", (int)line_num);
            return false;
        }
        ++line_num;
    }
    return true;
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

int server_config::get_timeout() const
{
    return 10;
}

server_config::~server_config()
{
}
