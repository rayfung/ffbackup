#include <stdio.h>
#include "ffprotocol.h"
#include "server.h"
#include "ffbuffer.h"

ffcmd::ffcmd()
{
}

ffcmd::~ffcmd()
{
}

cli_start_bak::cli_start_bak()
{
    this->state = cli_start_bak::state_recv_name;
    this->file_count = 0;
}

cli_start_bak::~cli_start_bak()
{
}

int cli_start_bak::update(connection *conn)
{
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

void ffprotocol::update(connection *conn)
{
    if(this->task_queue.size() > 0)
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
                task.cmd = new cli_start_bak();
                task.initial_event = FF_ON_READ;
                break;
            default:
                conn->state = connection::state_close;
                return;
        }
        this->append_task(task);
        this->event = task.initial_event;
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
