#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <cstdio>
#include <librsync.h>
#include <time.h>
#include "ffstorage.h"
#include "helper.h"

namespace ffstorage
{

/* 存储模块内部辅助函数，扫描目录中的普通文件和目录，并将结果添加到 result 里面 */
static void _scan_dir(const std::string &base, std::string dir, std::list<file_info> *result)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    dp = opendir((base + dir).c_str());
    if(dp == NULL)
        return;
    while((entry = readdir(dp)) != NULL)
    {
        std::string path;

        path = dir + std::string(entry->d_name);
        if(lstat((base + path).c_str(), &statbuf) < 0)
            continue;
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(".", entry->d_name) == 0 ||
                    strcmp("..", entry->d_name) == 0)
                continue;

            file_info info;
            info.type = 'd';
            info.path = path;
            result->push_back(info);

            _scan_dir(base, path + "/", result);
        }
        else if(S_ISREG(statbuf.st_mode))
        {
            file_info info;
            info.type = 'f';
            info.path = path;
            result->push_back(info);
        }
    }
    closedir(dp);
}

/* 准备好一个项目，创建必须的文件和目录 */
bool prepare(const char *project_name)
{
    std::string path;

    path.assign(project_name);

    rm_recursive(path + "/cache");
    mkdir((path + "/current").c_str(), 0775);
    mkdir((path + "/cache").c_str(), 0775);
    mkdir((path + "/cache/rc").c_str(), 0775);
    mkdir((path + "/history").c_str(), 0775);
    return true;
}

/* 目录扫描，忽略普通文件和目录之外的文件（如符号链接） */
void scan(const char *project_name, std::list<file_info> *result)
{
    std::string base;

    result->clear();
    base = std::string(project_name) + std::string("/current/");
    _scan_dir(base, std::string(), result);
}

int begin_add(const std::string &project_name, size_t index)
{
    std::string s = size2string(index);

    return creat((project_name + "/cache/" + s).c_str(), 0644);
}

void end_add(const std::string &project_name, const std::string &path)
{
}

int begin_delta(const std::string &project_name, size_t index)
{
    std::string s = size2string(index);

    return creat((project_name + "/cache/patch." + s).c_str(), 0644);
}

bool end_delta(const std::string &project_name, const std::string &path, size_t index)
{
    std::string basis_path = project_name + "/current/" + path;
    std::string patch_path = project_name + "/cache/patch." + size2string(index);
    std::string new_path   = project_name + "/cache/rc/" + size2string(index);

    return rsync_patch(basis_path, patch_path, new_path);
}

void dir_add(const std::string &project_name, const std::string &path)
{
    mkdir((project_name + "/cache/" + path).c_str(), 0775);
}

/* 计算指定项目的指定文件的 SHA-1 散列值 */
bool hash_sha1(const std::string &project_name, const std::string &path, void *hash)
{
    SHA_CTX ctx;
    FILE *fp;
    std::string tmp = project_name + "/current/" + path;
    size_t ret;
    char buffer[1024];

    fp = fopen(tmp.c_str(), "rb");
    if(fp == NULL)
        return false;
    if(SHA1_Init(&ctx) == 0)
        return false;
    while((ret = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        if(SHA1_Update(&ctx, buffer, ret) == 0)
        {
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    if(SHA1_Final((unsigned char *)hash, &ctx) == 0)
        return false;
    return true;
}

/* 生成指定项目的指定文件的 rsync 签名文件 */
FILE *rsync_sig(const std::string &project_name, const std::string &path)
{
    std::string tmp;
    FILE *basis_file;
    FILE *sig_file;
    size_t block_len = RS_DEFAULT_BLOCK_LEN;
    size_t strong_len = RS_DEFAULT_STRONG_LEN;
    rs_result ret;
    rs_stats_t stats;

    tmp = project_name + "/current/" + path;
    basis_file = fopen(tmp.c_str(), "rb"); //打开旧文件
    if(basis_file == NULL)
        return NULL;

    sig_file = tmpfile(); //创建签名文件
    if(sig_file == NULL)
    {
        fclose(basis_file);
        return NULL;
    }

    ret = rs_sig_file(basis_file, sig_file, block_len, strong_len, &stats);
    fclose(basis_file);
    if(ret)
    {
        fclose(sig_file);
        return NULL;
    }
    fflush(sig_file);
    rewind(sig_file);
    return sig_file;
}

bool rsync_patch(const std::string &basis_file_path, const std::string &patch_file_path,
                 const std::string &new_file_path)
{
    FILE *basis_file;
    FILE *delta_file;
    rs_result ret;
    FILE *new_file;
    rs_stats_t stats;

    basis_file = fopen(basis_file_path.c_str(), "rb");
    if(basis_file == NULL)
        return false;

    delta_file = fopen(patch_file_path.c_str(), "rb");
    if(delta_file == NULL)
    {
        fclose(basis_file);
        return false;
    }

    new_file = fopen(new_file_path.c_str(), "wb");
    if(new_file == NULL)
    {
        fclose(basis_file);
        fclose(delta_file);
        return false;
    }

    ret = rs_patch_file(basis_file, delta_file, new_file, &stats);
    fclose(basis_file);
    fclose(delta_file);
    fclose(new_file);
    return (ret == RS_DONE);
}

bool _write_list(const std::list<file_info> &file_list, std::string path)
{
    FILE *fp;
    std::list<file_info>::const_iterator iter;

    fp = fopen(path.c_str(), "wb");
    if(fp == NULL)
        return false;
    for(iter = file_list.begin(); iter != file_list.end(); ++iter)
    {
        fputc(iter->type, fp);
        fwrite(iter->path.c_str(), iter->path.size() + 1, 1, fp);
    }
    fclose(fp);
    return true;
}

bool write_patch_list(const std::string &project_name, const std::list<file_info> &file_list)
{
    return _write_list(file_list, project_name + "/cache/patch_list");
}

bool write_del_list(const std::string &project_name, const std::list<file_info> &file_list)
{
    return _write_list(file_list, project_name + "/cache/deletion_list");
}

bool write_add_list(const std::string &project_name, const std::list<file_info> &file_list)
{
    return _write_list(file_list, project_name + "/cache/addition_list");
}

/* 普通文件返回 'f'，目录返回 'd'，其它情况返回 '?' */
char get_file_type(const std::string &project_name, const std::string &path)
{
    struct stat buf;

    if(lstat((project_name + "/current/" + path).c_str(), &buf) == 0)
    {
        if(S_ISREG(buf.st_mode))
            return 'f';
        if(S_ISDIR(buf.st_mode))
            return 'd';
    }
    return '?';
}

/* 获取备份次数（包括未完成的） */
size_t get_history_qty(const std::string &project_name)
{
    size_t num;
    std::string base_path = project_name + "/history/";
    struct stat buf;

    for(num = 0; ; ++num)
    {
        if(lstat((base_path + size2string(num)).c_str(), &buf) < 0)
            return num;
    }
    return 0;
}

bool write_info(const std::string &project_name, size_t index)
{
    std::string path;
    int fd;
    uint32_t net_time;

    path = project_name + "/history/" + size2string(index) + "/info";
    fd = creat(path.c_str(), 0644);
    if(fd < 0)
        return false;
    net_time = hton32(time(NULL));
    write(fd, &net_time, 4);
    close(fd);
    return true;
}

std::list<std::string> get_project_list()
{
    std::list<std::string> prj_list;
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;

    dp = opendir(".");
    if(dp == NULL)
        return prj_list;
    while((entry = readdir(dp)) != NULL)
    {
        if(lstat(entry->d_name, &statbuf) < 0)
            continue;
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(".", entry->d_name) == 0 ||
                    strcmp("..", entry->d_name) == 0)
                continue;
            prj_list.push_back(std::string(entry->d_name));
        }
    }
    closedir(dp);
    return prj_list;
}

/* 获取项目备份历史，返回的列表中的元素表示备份完成时间，它是网络字节序的 */
std::list<uint32_t> get_project_time_line(const std::string &project_name)
{
    size_t index;
    std::string base = project_name + "/history/";
    std::string path;
    int fd;
    std::list<uint32_t> time_line;
    ssize_t ret;
    uint32_t finish_time;

    for(index = 0; ; ++index)
    {
        path = base + size2string(index) + "/info";
        fd = open(path.c_str(), O_RDONLY);
        if(fd < 0)
            break;
        ret = read(fd, &finish_time, 4);
        close(fd);
        if(ret != 4)
            break;
        time_line.push_back(finish_time);
    }
    return time_line;
}

}
