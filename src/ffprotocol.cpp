#include <algorithm>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ffprotocol.h"
#include "server.h"
#include "ffbuffer.h"
#include "helper.h"
#include "config.h"
#include "ffstorage.h"

ffcmd::ffcmd()
{
}

ffcmd::~ffcmd()
{
}

start_backup::start_backup()
{
}

start_backup::~start_backup()
{
}

int start_backup::update(connection *conn)
{
    bool found;
    size_t n;
    char *prj = NULL;
    std::list<file_info> result;

    n = conn->in_buffer.find('\0', &found);
    if(!found)
        return FF_AGAIN;
    if(n == 0)
        return FF_ERROR;
    prj = new char[n + 1];
    conn->in_buffer.get(prj, 0, n + 1);
    conn->in_buffer.pop_front(n + 1);
    if(!is_path_safe(std::string(prj)))
    {
        delete[] prj;
        return FF_ERROR;
    }
    ffstorage::prepare(prj);
    ffstorage::scan(prj, &result);

    fprintf(stderr, "\n[BEGIN dump]\n");
    for(std::list<file_info>::iterator iter = result.begin();
        iter != result.end(); ++iter)
    {
        fprintf(stderr, "path=[%s]; type=%c\n", iter->path.c_str(), iter->type);
    }
    fprintf(stderr, "[END dump]\n\n");

    //后续操作需要用到这个项目名称
    conn->processor.project_name.assign(prj);
    delete[] prj;
    return FF_DONE;
}

no_operation::no_operation()
{
}

no_operation::~no_operation()
{
}

int no_operation::update(connection *conn)
{
    char buf[256];
    size_t count;
    while(conn->in_buffer.get_size() > 0)
    {
        count = conn->in_buffer.get(buf, 0, sizeof(buf));
        conn->in_buffer.pop_front(count);
        conn->out_buffer.push_back(buf, count);
    }
    return FF_AGAIN;
}

ffprotocol::ffprotocol()
{
    this->event = FF_ON_READ;
}

ffprotocol::~ffprotocol()
{
    this->reset();
}

void ffprotocol::execute_task(connection *conn)
{
    int ret;
    fftask task = this->task_queue.front();
    ret = task.cmd->update(conn);
    if(ret == FF_DONE)
    {
        if(task.cmd)
            delete task.cmd;
        this->task_queue.pop();
        if(this->task_queue.empty())
            this->event = FF_ON_READ;
        else
            this->event = this->task_queue.front().initial_event;
    }
    else if(ret == FF_ERROR)
        conn->state = connection::state_close;
}

void ffprotocol::update(connection *conn)
{
    if(this->task_queue.size() > 0)
        this->execute_task(conn);
    else
    {
        if(conn->in_buffer.get_size() < 2)
            return;

        unsigned char hdr[2] = {0, 0};
        fftask task;

        conn->in_buffer.get(hdr, 0, 2);
        conn->in_buffer.pop_front(2);
        fprintf(stderr, "version = %02x; command=%02x\n", hdr[0], hdr[1]);
        task.version = hdr[0];
        switch(hdr[1])
        {
            case 0x00:
                task.cmd = new no_operation();
                task.initial_event = FF_ON_READ;
                break;
            case 0x01:
                this->project_name.clear();
                task.cmd = new start_backup();
                task.initial_event = FF_ON_READ;
                break;
            default:
                conn->state = connection::state_close;
                return;
        }
        this->append_task(task);
        this->event = task.initial_event;

        if(this->event == FF_ON_READ && conn->in_buffer.get_size() > 0)
            this->execute_task(conn);
    }
}

void ffprotocol::append_task(fftask task)
{
    this->task_queue.push(task);
}

bool ffprotocol::wait_for_readable()
{
    return (this->event == FF_ON_READ);
}
bool ffprotocol::wait_for_writable()
{
    return (this->event == FF_ON_WRITE);
}

void ffprotocol::set_event(int ev)
{
    this->event = ev;
}

void ffprotocol::reset()
{
    this->event = FF_ON_READ;
    while(!this->task_queue.empty())
    {
        fftask task = this->task_queue.front();
        if(task.cmd)
            delete task.cmd;
        this->task_queue.pop();
    }
}
