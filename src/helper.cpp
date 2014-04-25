#include <algorithm>
#include <sstream>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include "helper.h"

#define FF_LITTLE_ENDIAN 0
#define FF_BIG_ENDIAN 1

/* 以十六进制的形式输出数据到标准错误输出，此函数仅用于调试 */
void dump_data(void *data, size_t size)
{
    unsigned char *ptr = (unsigned char *)data;
    size_t i;
    for(i = 0; i < size; ++i)
        fprintf(stderr, "%02X ", (int)ptr[i]);
}

/**
 * 将一个路径以 '/' 为分隔符分割成若干个部分，如果路径以 '/' 开头，那么它会被当成是第一部分
 * 分割后的任何部分都不会再包含 '/'，除非参数是一个绝对路径，此时，第一部分是单个字符 '/'
 *
 * 例子：
 *   "/var/log" -> {"/", "var", "log"}
 *   "history/0/" -> {"history", "0"}
 *   "./cache///patch" -> {".", "cache", "patch"}
 */
std::list<std::string> split_path(const std::string &path)
{
    size_t path_len;
    const char *path_c;
    std::list<std::string> component_list;
    size_t i;
    size_t pos;
    size_t len;
    int state;

    path_len = path.size();
    path_c = path.c_str();

    if(path_c[0] == '/')
        component_list.push_back(std::string("/"));
    state = 0;
    for(i = 0; i <= path_len;)
    {
        char ch = path_c[i];
        switch(state)
        {
        case 0:
            if(ch == '/' || ch == '\0')
            {
                ++i;
                break;
            }
        case 1:
            pos = i;
            len = 0;
            state = 2;
        case 2:
            if(ch == '/' || ch == '\0')
            {
                component_list.push_back(std::string(path_c + pos, len));
                state = 0;
            }
            else
            {
                ++len;
                ++i;
            }
            break;
        }
    }
    return component_list;
}

/**
 * 检查路径是否"安全"
 *
 * 一个"安全"的路径必须满足以下所有条件：
 * 1.路径不为空
 * 2.路径不包含空字符
 * 3.不是绝对路径
 * 4.路径中所有组成部分都不能为 ".." 或者 "."
 *
 */
bool is_path_safe(const std::string &path)
{
    std::list<std::string> component_list;

    if(path.empty())
        return false;
    if(path.find('\0') != std::string::npos)
        return false;

    component_list = split_path(path);
    if(component_list.size() > 0 && component_list.front() == std::string("/"))
        return false;
    if(std::find(component_list.begin(), component_list.end(), std::string(".."))
            != component_list.end())
        return false;
    if(std::find(component_list.begin(), component_list.end(), std::string("."))
            != component_list.end())
        return false;
    return true;
}

/* 检查项目名是否合法 */
bool is_project_name_safe(const char *prj)
{
    if(prj[0] == '\0')
        return false; //项目名称不能为空
    while(prj[0])
    {
        if(prj[0] == '/' || prj[0] == '.')
            return false;
        ++prj;
    }
    return true;
}

uint64_t get_file_size(FILE *fp)
{
    struct stat buf;

    if(fp == NULL)
        return 0;
    if(fstat(fileno(fp), &buf) < 0)
        return 0;
    return buf.st_size;
}

std::string size2string(size_t size)
{
    std::ostringstream s;

    s << size;
    return s.str();
}

bool rm_recursive(const std::string &path)
{
    pid_t pid;

    pid = fork();
    if(pid < 0)
        return false;
    if(pid == 0)
    {
        execl("/bin/rm", "/bin/rm", "-rf", "--", path.c_str(), (char *)NULL);
        exit(0);
    }
    else
    {
        int status;
        waitpid(pid, &status, 0);
    }
    return true;
}

/* 首先尝试创建硬链接，如果失败，则直接复制文件 */
bool link_or_copy(const std::string &src_path, const std::string &dst_path)
{
    rm_recursive(dst_path);
    if(link(src_path.c_str(), dst_path.c_str()) < 0)
        return copy_file(src_path, dst_path);
    return true;
}

/* 复制文件，如果目标路径已经存在，那么它会先被清空 */
bool copy_file(const std::string &src_path, const std::string &dst_path)
{
    int src_fd, dst_fd;
    char buffer[1024];
    ssize_t ret;
    bool ok = true;

    src_fd = open(src_path.c_str(), O_RDONLY);
    if(src_fd < 0)
        return false;

    dst_fd = creat(dst_path.c_str(), 0644);
    if(dst_fd < 0)
    {
        close(src_fd);
        return false;
    }

    while((ret = read(src_fd, buffer, sizeof(buffer))) > 0)
    {
        if(write(dst_fd, buffer, ret) != ret)
        {
            close(src_fd);
            close(dst_fd);
            return false;
        }
    }

    if(close(src_fd) < 0)
        ok = false;
    if(close(dst_fd) < 0)
        ok = false;
    return ok;
}

int get_byte_order()
{
    uint16_t k = 0x0102;
    unsigned char *ptr = (unsigned char *)&k;
    if(ptr[0] == 0x02)
        return FF_LITTLE_ENDIAN;
    else
        return FF_BIG_ENDIAN;
}

uint16_t ntoh16(uint16_t net)
{
    return ntohs(net);
}

uint16_t hton16(uint16_t host)
{
    return htons(host);
}

uint32_t ntoh32(uint32_t net)
{
    return ntohl(net);
}

uint32_t hton32(uint32_t host)
{
    return htonl(host);
}

uint64_t ntoh64(uint64_t net)
{
    uint64_t u = net;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_net = (uint8_t *)&net;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_net[j];
    }
    return u;
}

uint64_t hton64(uint64_t host)
{
    uint64_t u = host;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_host = (uint8_t *)&host;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_host[j];
    }
    return u;
}

/* a + b */
struct timespec fftime_add(struct timespec a, struct timespec b)
{
    struct timespec c;
    long t;

    t = a.tv_nsec + b.tv_nsec;
    c.tv_sec = a.tv_sec + b.tv_sec + t / 1000000000L;
    c.tv_nsec = t % 1000000000L;
    return c;
}

/* 如果 a >= b，则返回 a - b；否则，返回 0 */
struct timespec fftime_sub(struct timespec a, struct timespec b)
{
    struct timespec c;

    c.tv_sec  = 0;
    c.tv_nsec = 0;
    if(a.tv_sec < b.tv_sec)
        return c;
    if(a.tv_sec == b.tv_sec)
    {
        if(a.tv_nsec <= b.tv_nsec)
            return c;
        c.tv_nsec = a.tv_nsec - b.tv_nsec;
        return c;
    }
    else
    {
        if(a.tv_nsec < b.tv_nsec)
        {
            c.tv_sec  = a.tv_sec - b.tv_sec - 1;
            c.tv_nsec = 1000000000L - b.tv_nsec + a.tv_nsec;
        }
        else
        {
            c.tv_sec  = a.tv_sec  - b.tv_sec;
            c.tv_nsec = a.tv_nsec - b.tv_nsec;
        }
        return c;
    }
}

//通过 fcntl 来为整个文件加锁或者解锁
int fcntl_lock_wrapper(int fd, int type)
{
    struct flock lock;

    lock.l_type   = type;
    lock.l_start  = 0;
    lock.l_len    = 0;
    lock.l_whence = SEEK_SET;
    return fcntl(fd, F_SETLK, &lock);
}

//加上互斥写锁
int fcntl_write_lock(int fd)
{
    return fcntl_lock_wrapper(fd, F_WRLCK);
}

//解除文件上的所有锁
int fcntl_unlock(int fd)
{
    return fcntl_lock_wrapper(fd, F_UNLCK);
}
