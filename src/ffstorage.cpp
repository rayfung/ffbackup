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
#include "ffbuffer.h"

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

/**
 * 如果能够完整地读取所有元素，则返回 true，否则返回 false
 * 并且将读取到的元素存放在 file_list 中
 */
bool _read_list(const std::string &path, std::list<file_info> *file_list)
{
    ffbuffer buffer;
    int fd;
    char tmp[1024];
    ssize_t ret;
    bool found;
    size_t pos;

    file_list->clear();
    fd = open(path.c_str(), O_RDONLY);
    if(fd < 0)
        return true;
    while((ret = read(fd, tmp, sizeof(tmp))) > 0)
        buffer.push_back(tmp, ret);
    close(fd);

    while(buffer.get_size() > 0)
    {
        char *ptr;
        file_info info;

        pos = buffer.find('\0', &found);
        if(!found || pos < 2)
            return false;
        ptr = new char[pos + 1];
        buffer.get(ptr, 0, pos + 1);
        buffer.pop_front(pos + 1);
        info.type = ptr[0];
        info.path.assign(ptr + 1);
        delete[] ptr;
        if(info.type != 'f' && info.type != 'd')
            return false;
        file_list->push_back(info);
    }
    return true;
}

bool _restore(const std::string &project_name,
              const std::string &storage_path, const std::string &history_path)
{
    std::list<file_info> patch_list;
    std::list<file_info> deletion_list;
    std::list<file_info> addition_list;
    std::list<file_info>::iterator iter;
    size_t index;

    if(!_read_list(history_path + "/patch_list", &patch_list))
        return false;
    if(!_read_list(history_path + "/deletion_list", &deletion_list))
        return false;
    if(!_read_list(history_path + "/addition_list", &addition_list))
        return false;

    //rsync patch
    index = 0;
    for(iter = patch_list.begin(); iter != patch_list.end(); ++iter)
    {
        std::string basis;
        std::string patch;
        std::string output;

        basis = storage_path + "/" + iter->path;
        patch = history_path + "/patch." + size2string(index);
        output = project_name + "/tmp_ffbackup";
        rsync_patch(basis, patch, output);
        rename(output.c_str(), basis.c_str());
        ++index;
    }

    //process deletion list
    for(iter = deletion_list.begin(); iter != deletion_list.end(); ++iter)
    {
        rm_recursive(storage_path + "/" + iter->path);
    }

    //process addition list
    index = 0;
    for(iter = addition_list.begin(); iter != addition_list.end(); ++iter)
    {
        std::string path(storage_path + "/" + iter->path);
        if(iter->type == 'f')
            copy_file(history_path + "/" + size2string(index), path);
        else if(iter->type == 'd')
            mkdir(path.c_str(), 0775);
        ++index;
    }
    return true;
}

/**
 *
 * 恢复到历史 #id，并将恢复后的文件列表存入 file_list
 * 如果恢复发生错误，则返回空字符串，否则返回恢复的目录路径
 *
 */
std::string begin_restore(const std::string &prj, size_t id, std::list<file_info> *file_list)
{
    std::string base = prj + "/tmp";
    size_t count;
    size_t index;

    file_list->clear();
    rm_recursive(base);
    if(mkdir(base.c_str(), 0775) < 0)
        return std::string();
    count = get_history_qty(prj);
    if(id >= count)
        return std::string();
    if(count > 0 && id == count - 1) //如果是最近一次的历史，则直接返回 current 目录中的文件
    {
        scan(prj.c_str(), file_list);
        return prj + "/current";
    }
    for(index = 0; index <= id; ++index)
    {
        if(!_restore(prj, base, prj + "/history/" + size2string(index)))
            return std::string();
    }
    _scan_dir(base + "/", std::string(), file_list);
    return base;
}

void end_restore(const std::string &prj)
{
    rm_recursive(prj + "/tmp");
}

/**
 *
 * 检查、修复 corruption
 *
 * (1) /history/#/info 完整：如果 /cache 目录存在，删除掉即可
 * (2) /history/#/info 不完整：此时并未发生 corruption，重写 info 文件即可
 * (3) /history/#/info 不存在：此时可能发生 corruption，必须重新备份一次
 *
 */
void storage_check()
{
    size_t id;
    std::string history_path;
    std::list<std::string> prj_list;
    std::list<std::string>::iterator prj;
    size_t index;
    std::list<file_info>::iterator iter;
    std::list<file_info> patch_list;
    std::list<file_info> deletion_list;
    std::list<file_info> addition_list;

    fprintf(stderr, "storage checking started\n");
    prj_list = ffstorage::get_project_list();
    for(prj = prj_list.begin(); prj != prj_list.end(); ++prj)
    {
        struct stat buf;

        fprintf(stderr, "checking %s : ", prj->c_str());
        fflush(stderr);
        id = ffstorage::get_history_qty(*prj);
        if(id == 0)
            continue;
        --id;
        history_path = *prj + "/history/" + size2string(id);
        if(lstat((history_path + "/info").c_str(), &buf) == 0)
        {
            if(S_ISREG(buf.st_mode) && buf.st_size == 4)
            {
                //info 完整，对应于(1)
                if(lstat((*prj + "/cache").c_str(), &buf) == 0)
                    rm_recursive(*prj + "/cache");
                fprintf(stderr, "OK\n");
            }
            else
            {
                write_info(*prj, id); //info 存在但不完整，对应于(2)
                fprintf(stderr, "history information repaired\n");
            }
            continue;
        }

        //info 不存在，对应于(3)
        fprintf(stderr, "corruption detected");
        fflush(stderr);

        //删除残留的锁文件
        rm_recursive(*prj + "/lock.0");
        rm_recursive(*prj + "/lock.1");

        _read_list(history_path + "/patch_list", &patch_list);
        _read_list(history_path + "/deletion_list", &deletion_list);
        _read_list(history_path + "/addition_list", &addition_list);

        //将 patch 后的文件移动到 current 目录中
        index = 0;
        for(iter = patch_list.begin(); iter != patch_list.end(); ++iter)
        {
            rename((history_path + "/rc/" + size2string(index)).c_str(),
                   (*prj + "/current/" + iter->path).c_str());
            ++index;
        }
        //递归删除列表中的文件
        for(iter = deletion_list.begin(); iter != deletion_list.end(); ++iter)
            rm_recursive(*prj + "/current/" + iter->path);
        //将新增的文件复制到相应目录下
        index = 0;
        for(iter = addition_list.begin(); iter != addition_list.end(); ++iter)
        {
            if(iter->type == 'f')
                copy_file(history_path + "/" + size2string(index),
                          *prj + "/current/" + iter->path);
            else if(iter->type == 'd')
                mkdir((*prj + "/current/" + iter->path).c_str(), 0775);
            ++index;
        }
        ffstorage::write_info(*prj, id);
        fprintf(stderr, ", repaired\n");
    }
    fprintf(stderr, "storage checking done!\n");
}

}
