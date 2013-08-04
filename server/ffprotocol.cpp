#include <stdio.h>
#include "ffprotocol.h"
#include "server.h"
#include "ffbuffer.h"
#include "helper.h"

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
    size_t n;
    size_t i;
    char buf[64];
    while(1)
    {
        switch(this->state)
        {
            case cli_start_bak::state_recv_name:
                if(conn->in_buffer.get_size() == 0)
                    return FF_AGAIN;
                n = conn->in_buffer.get(buf, 0, sizeof(buf));
                //找出需要复制多少个字节
                for(i = 0; i < n && buf[i]; ++i)
                    ;
                this->project_name += std::string(buf, i);
                if(i < n) //如果找到了空字符
                {
                    conn->in_buffer.pop_front(i + 1); //把空字符也移除掉
                    this->state = cli_start_bak::state_recv_size;
                }
                else
                    conn->in_buffer.pop_front(i);
                break;

            case cli_start_bak::state_recv_size:
                if(conn->in_buffer.get_size() < 4)
                    return FF_AGAIN;
                conn->in_buffer.get(&this->file_count, 0, 4);
                conn->in_buffer.pop_front(4);
                //将网络字节序的整型数据转换为本机字节序
                this->file_count = ntoh32(this->file_count);
                if(this->file_count == 0)
                    this->state = cli_start_bak::state_done;
                else
                    this->state = cli_start_bak::state_recv_path;
                break;

            case cli_start_bak::state_recv_path:
                if(conn->in_buffer.get_size() == 0)
                    return FF_AGAIN;
                n = conn->in_buffer.get(buf, 0, sizeof(buf));
                //找出需要复制多少个字节
                for(i = 0; i < n && buf[i]; ++i)
                    ;
                this->tmp_file_info.path += std::string(buf, i);
                if(i < n) //如果找到了空字符
                {
                    conn->in_buffer.pop_front(i + 1); //把空字符也移除掉
                    this->state = cli_start_bak::state_recv_type;
                }
                else
                    conn->in_buffer.pop_front(i);
                break;

            case cli_start_bak::state_recv_type:
                if(conn->in_buffer.get_size() < 1)
                    return FF_AGAIN;
                conn->in_buffer.get(&this->tmp_file_info.type, 0, 1);
                conn->in_buffer.pop_front(1);
                if(this->tmp_file_info.type != 'f' && this->tmp_file_info.type != 'd')
                    return FF_ERROR;
                if(this->tmp_file_info.type == 'f')
                    this->state = cli_start_bak::state_recv_hash;
                else
                    this->state = cli_start_bak::state_item_done;
                break;

            case cli_start_bak::state_recv_hash:
                if(conn->in_buffer.get_size() < 20)
                    return FF_AGAIN;
                conn->in_buffer.get(this->tmp_file_info.sha1, 0, 20);
                conn->in_buffer.pop_front(20);
                this->state = cli_start_bak::state_item_done;
                break;

            case cli_start_bak::state_item_done:
                this->file_list.push_back(this->tmp_file_info);
                this->file_count--;

                if(this->file_count == 0)
                    this->state = cli_start_bak::state_done;
                else
                {
                    this->tmp_file_info.path.clear();
                    this->state = cli_start_bak::state_recv_path;
                }
                break;

            case cli_start_bak::state_done:
                conn->out_buffer.push_back("\x01\x00", 2);
                this->dump();
                fprintf(stderr, "task start_backup done\n");
                return FF_DONE;
        }
    }
    return FF_AGAIN;
}

void cli_start_bak::dump()
{
    std::list<file_info>::iterator iter;
    fprintf(stderr, "\n[dump] %s:\n", this->project_name.c_str());
    for(iter = this->file_list.begin(); iter != this->file_list.end(); ++iter)
    {
        fprintf(stderr, "%s; %c; ", iter->path.c_str(), iter->type);
        if(iter->type == 'f')
            dump_data(iter->sha1, 20);
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
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
                task.cmd = new cli_start_bak();
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
