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
    int max_connection;                //最大 TCP 连接数
    char backup_root[path_max];        //所有项目的存储目录
    enum protocol protocol;            //使用的 SSL/TLS 协议版本
    char host[host_max];               //监听套接字绑定的地址
    char service[service_max];         //监听套接字绑定的服务（端口）
    char ca_file[path_max];            //CA 公钥文件路径
    char cert_file[path_max];          //服务端公钥文件路径
    char key_file[path_max];           //服务端私钥文件路径
    char key_file_passwd[passwd_max];  //服务端私钥文件密码
};

#endif
