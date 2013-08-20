#ifndef FFPROTOCOL_H
#define FFPROTOCOL_H

#include <string>
#include <list>
#include <queue>

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

class start_backup : public ffcmd
{
public:
    start_backup();
    ~start_backup();
    int update(connection *conn);
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

public:
    std::string project_name;

private:
    int event;
    std::queue<fftask> task_queue;
};

#endif
