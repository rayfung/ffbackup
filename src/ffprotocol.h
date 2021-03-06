#ifndef FFPROTOCOL_H
#define FFPROTOCOL_H

#include <string>
#include <list>
#include <queue>
#include <stdint.h>
#include <cstdio>
#include "task_scheduler.h"
#include "ffstorage.h"

#define FF_DONE 0
#define FF_AGAIN 1
#define FF_ERROR 2

#define FF_ON_READ 1
#define FF_ON_WRITE 2
#define FF_ON_TIMEOUT 4

class connection;

class ffcmd
{
public:
    ffcmd();
    virtual ~ffcmd();
    virtual int update(connection *conn) = 0;
};

/* 处理协议中的“开始备份”命令 */
class start_backup : public ffcmd
{
public:
    start_backup();
    ~start_backup();
    int update(connection *conn);
};

/* 在另外一个线程中处理文件的散列值的计算 */
class get_hash_task : public ff_sched::ff_task
{
public:
    get_hash_task(const std::string &prj, const std::list<std::string> &file_list);
    ~get_hash_task();
    void run();
    bool is_finished(); //not thread-safe

public:
    std::list<char *> sha1_list;

private:
    std::list<std::string> file_list;
    std::string project_name;
    bool finished;
};

/* 处理协议中的“获取散列值”命令 */
class get_hash : public ffcmd
{
public:
    get_hash();
    ~get_hash();
    int update(connection *conn);

private:
    uint32_t size;
    std::list<std::string> file_list;
    enum
    {
        state_recv_size, state_recv_path, state_item_done,
        state_wait_bg_task
    }state;
    get_hash_task *task;
    bool task_owner;
};

/* 在另外一个线程中处理 rsync 签名的计算任务 */
class get_sig_task : public ff_sched::ff_task
{
public:
    get_sig_task(const std::string &prj, const std::string &path);
    ~get_sig_task();
    void run();
    bool is_finished(); //not thread-safe

public:
    FILE *sig_file;

private:
    std::string file_path;
    std::string project_name;
    bool finished;
};

/* 处理协议中的“获取签名”命令 */
class get_signature : public ffcmd
{
public:
    get_signature();
    ~get_signature();
    int update(connection *conn);

private:
    uint32_t size;
    std::string file_path;
    enum
    {
        state_recv_size, state_recv_path, state_item_done,
        state_wait_bg_task
    }state;
    get_sig_task *task;
    bool task_owner;
};

class send_delta : public ffcmd
{
public:
    send_delta();
    ~send_delta();
    int update(connection *conn);

private:
    enum
    {
        state_recv_size, state_recv_path,
        state_recv_data_size, state_recv_data,
        state_item_done
    }state;
    uint32_t size;
    size_t index;
    std::string path;
    uint64_t data_size;
    int file_fd;
    std::list<file_info> file_list;
};

class send_deletion : public ffcmd
{
public:
    send_deletion();
    ~send_deletion();
    int update(connection *conn);

private:
    std::list<file_info> file_list;
    uint32_t size;
    enum
    {
        state_recv_size, state_recv_path, state_item_done
    }state;
};

class send_addition : public ffcmd
{
public:
    send_addition();
    ~send_addition();
    int update(connection *conn);

private:
    enum
    {
        state_recv_size, state_recv_path, state_recv_type,
        state_recv_data_size, state_recv_data,
        state_item_done
    }state;
    uint32_t size;
    std::string path;
    char type;
    uint64_t data_size;
    int file_fd;
    std::list<file_info> file_list;
    size_t index;
};

class finish_bak_task : public ff_sched::ff_task
{
public:
    finish_bak_task(const std::string &prj, uint64_t task_id,
                    const std::list<file_info> &patch_list,
                    const std::list<file_info> &deletion_list,
                    const std::list<file_info> &addition_list);
    ~finish_bak_task();
    void run();
    bool is_finished(); //not thread-safe

private:
    std::string project_name;
    uint64_t task_id;
    std::list<file_info> patch_list;
    std::list<file_info> deletion_list;
    std::list<file_info> addition_list;
    bool finished;
};

class finish_backup : public ffcmd
{
public:
    finish_backup();
    ~finish_backup();
    int update(connection *conn);

private:
    finish_bak_task *task;
    bool task_owner;
};

class client_get_prj : public ffcmd
{
public:
    client_get_prj();
    ~client_get_prj();
    int update(connection *conn);
};

class client_get_time_line : public ffcmd
{
public:
    client_get_time_line();
    ~client_get_time_line();
    int update(connection *conn);
};

class client_restore_task : public ff_sched::ff_task
{
public:
    client_restore_task(const std::string &prj, uint32_t id, uint64_t task_id);
    ~client_restore_task();
    void run();
    bool is_finished(); //not thread-safe

public:
    std::list<file_info> file_list;
    std::string base_path;

private:
    bool finished;
    std::string prj;
    uint32_t id;
    uint64_t task_id;
};

class client_restore : public ffcmd
{
public:
    client_restore();
    ~client_restore();
    int update(connection *conn);

private:
    enum
    {
        state_recv_prj, state_recv_id,
        state_wait, state_response,
        state_send_file, state_item_done
    }state;
    std::string prj;
    uint32_t id;
    client_restore_task *task;
    bool task_owner;
    int fd;
    uint64_t file_size;
};

class fftask
{
public:
    int version;
    ffcmd *cmd;
    int initial_event;
};

class ffprotocol
{
public:
    ffprotocol();
    ~ffprotocol();
    void update(connection *conn);
    void reset();
    void append_task(fftask task);
    bool wait_for_readable();
    bool wait_for_writable();
    bool wait_for_timeout();
    void set_event(int ev);

private:
    void execute_task(connection *conn);

public:
    std::string project_name;
    uint64_t task_id;
    std::list<file_info> patch_list;
    std::list<file_info> deletion_list;
    std::list<file_info> addition_list;

private:
    int event;
    std::queue<fftask> task_queue;
};

#endif
