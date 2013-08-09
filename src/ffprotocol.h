#ifndef FFPROTOCOL_H
#define FFPROTOCOL_H

#include <string>
#include <list>
#include <queue>
#include "data_types.h"

#define FF_DONE 0
#define FF_AGAIN 1
#define FF_ERROR 2

#define FF_ON_READ 1
#define FF_ON_WRITE 2

class connection;

class ffcmd
{
public:
    ffcmd();
    virtual ~ffcmd();
    virtual int update(connection *conn) = 0;
};

class cli_start_bak : public ffcmd
{
public:
    cli_start_bak();
    ~cli_start_bak();
    int update(connection *conn);

protected:
    void dump();
    void generate_task(connection *conn);

protected:
    std::string project_name;
    uint32_t file_count;
    std::list<file_info> file_list;

private:
    enum {state_recv_name, state_recv_size, state_recv_path,
        state_recv_type, state_recv_hash, state_item_done, state_done} state;
    file_info tmp_file_info;
};

class ser_request_whole : public ffcmd
{
public:
    ser_request_whole(const std::list<std::string> &file_list);
    ~ser_request_whole();
    int update(connection *conn);

private:
    std::list<std::string> file_list;
    int file_fd;
    uint64_t file_size;
    bool size_read;
    enum {state_send_path, state_read_data, state_item_done}state;
};

class no_operation : public ffcmd
{
public:
    no_operation();
    ~no_operation();
    int update(connection *conn);
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
    void set_event(int ev);

private:
    void execute_task(connection *conn);

private:
    int event;
    std::queue<fftask> task_queue;
};

#endif
