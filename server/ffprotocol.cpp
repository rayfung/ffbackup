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

fftask::fftask()
{
    this->version = -1;
    this->cmd = NULL;
    this->events = 0;
}

fftask::~fftask()
{
    delete this->cmd;
}

ffprotocol::ffprotocol()
{
}

ffprotocol::~ffprotocol()
{
    this->reset();
}

int ffprotocol::update(connection *conn)
{
    if(this->task_queue.size() > 0)
    {
        int ret;
        fftask task = this->task_queue.front();
        ret = task.cmd->update(conn);
        if(ret == FF_DONE)
            this->task_queue.pop();
        return ret;
    }
    else
    {
        if(conn->in_buffer.get_size() < 2)
            return FF_AGAIN;

        unsigned char hdr[2] = {0, 0};
        fftask task;

        conn->in_buffer.get(hdr, 0, 2);
        task.version = hdr[0];
        switch(hdr[1])
        {
            case 0x01:
                task.cmd = new cli_start_bak();
                task.events = FF_ON_READ;
                break;
            default:
                return FF_ERROR;
        }
        this->append_task(task);
        return FF_AGAIN;
    }
}

void ffprotocol::append_task(fftask task)
{
    this->task_queue.push(task);
}

void ffprotocol::reset()
{
    while(!this->task_queue.empty())
    {
        this->task_queue.pop();
    }
}
