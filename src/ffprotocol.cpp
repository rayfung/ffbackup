#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ffprotocol.h"
#include "server.h"
#include "ffbuffer.h"
#include "helper.h"
#include "config.h"
#include "task_lock.h"

extern ff_sched::task_scheduler *g_task_sched;

/* 从缓冲区中取出一个空字符结尾的字符串，如果能够完整取出的话，那么返回 true，否则返回 false */
static bool get_protocol_string(ffbuffer *in, std::string *s)
{
    bool found;
    size_t pos;
    char *ptr;

    s->clear();
    pos = in->find('\0', &found);
    if(!found)
        return false;
    ptr = new char[pos + 1];
    in->get(ptr, 0, pos + 1);
    in->pop_front(pos + 1);
    s->assign(ptr);
    delete[] ptr;
    return true;
}

static bool get_protocol_char(ffbuffer *in, char *c)
{
    if(in->get_size() == 0)
        return false;
    in->get(c, 0, 1);
    in->pop_front(1);
    return true;
}

/* 取出一个网络字节序的 32 位整数，并转换为本机字节序 */
static bool get_protocol_uint32(ffbuffer *in, uint32_t *u32)
{
    if(in->get_size() < 4)
        return false;
    in->get(u32, 0, 4);
    in->pop_front(4);
    *u32 = ntoh32(*u32);
    return true;
}

/* 取出一个网络字节序的 64 位整数，并转换为本机字节序 */
static bool get_protocol_uint64(ffbuffer *in, uint64_t *u64)
{
    if(in->get_size() < 8)
        return false;
    in->get(u64, 0, 8);
    in->pop_front(8);
    *u64 = ntoh64(*u64);
    return true;
}

ffcmd::ffcmd()
{
}

ffcmd::~ffcmd()
{
}

/**
 *
 * [1] start_backup
 *
 * 描述：客户端开始一次备份，发送备份项目名称
 * 参数：项目名称（String）
 * 返回：List<文件相对路径（String）；文件类型（char）>
 * 错误：无，该操作一定成功
 * 说明：项目名称不可以为空并且不可以包含以下字符：斜杠（/）、点（.）
 *
 */

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
    std::list<file_info>::iterator iter;
    uint64_t task_id;

    n = conn->in_buffer.find('\0', &found);
    if(!found)
        return FF_AGAIN;
    if(n == 0)
        return FF_ERROR;
    prj = new char[n + 1];
    conn->in_buffer.get(prj, 0, n + 1);
    conn->in_buffer.pop_front(n + 1);
    if(!is_project_name_safe(prj))
    {
        delete[] prj;
        return FF_ERROR;
    }
    mkdir(prj, 0775); //创建项目目录(权限为 rwxrwxr-x)
    task_id = random();
    if(!ff_trylock(std::string(prj), task_id))
    {
        delete[] prj;
        return FF_ERROR;
    }
    //后续操作需要用到这个项目名称
    conn->processor.project_name.assign(prj);
    conn->processor.task_id = task_id;
    if(!ffstorage::prepare(prj))
    {
        delete[] prj;
        return FF_ERROR;
    }
    ffstorage::scan(prj, &result);

    fprintf(stderr, "\n[BEGIN dump]\n");
    for(iter = result.begin(); iter != result.end(); ++iter)
    {
        fprintf(stderr, "path=[%s]; type=%c\n", iter->path.c_str(), iter->type);
    }
    fprintf(stderr, "[END dump]\n\n");

    delete[] prj;

    char hdr[2] = {2, 0};
    uint32_t size;

    size = hton32((uint32_t)result.size());
    conn->out_buffer.push_back(hdr, 2);
    conn->out_buffer.push_back(&size, 4);
    for(iter = result.begin(); iter != result.end(); ++iter)
    {
        std::string path = iter->path;
        char type = iter->type;

        conn->out_buffer.push_back(path.data(), path.size());
        conn->out_buffer.push_back("\0", 1);
        conn->out_buffer.push_back(&type, 1);
    }
    return FF_DONE;
}

/**
 *
 * [2] get_hash
 *
 * 描述：获取文件哈希值（SHA-1）
 * 参数：List<文件相对路径（String）>
 * 返回：List<SHA-1（20字节）>
 *
 */

get_hash_task::get_hash_task(const std::string &prj, const std::list<std::string> &file_list)
{
    this->file_list = file_list;
    this->project_name = prj;
    this->finished = false;
}

get_hash_task::~get_hash_task()
{
    std::list<char *>::iterator iter;
    for(iter = this->sha1_list.begin(); iter != this->sha1_list.end(); ++iter)
        delete[] *iter;
}

void get_hash_task::run()
{
    std::list<std::string>::iterator iter;
    char *sha1;

    for(iter = this->file_list.begin(); iter != this->file_list.end(); ++iter)
    {
        if(this->is_canceled())
            return;
        sha1 = new char[20];
        if(!ffstorage::hash_sha1(this->project_name, *iter, sha1))
        {
            delete[] sha1;
            return;
        }
        this->sha1_list.push_back(sha1);
    }
    this->finished = true;
}

bool get_hash_task::is_finished()
{
    return this->finished;
}

get_hash::get_hash()
{
    this->state = state_recv_size;
    this->task = NULL;
    this->task_owner = true;
}

get_hash::~get_hash()
{
    if(this->task)
    {
        if(this->task_owner)
            delete this->task;
        else
            g_task_sched->cancel(this->task);
    }
}

int get_hash::update(connection *conn)
{
    char hdr[2] = {2, 0};
    uint32_t net_size;
    std::string path;
    std::list<char *>::iterator iter;

    if(conn->processor.project_name.empty())
        return FF_ERROR;
    while(1)
    {
        switch(this->state)
        {
        case state_recv_size:
            if(!get_protocol_uint32(&conn->in_buffer, &this->size))
                return FF_AGAIN;
            net_size = hton32(this->size);
            conn->out_buffer.push_back(hdr, 2);
            conn->out_buffer.push_back(&net_size, 4);
            if(this->size == 0)
                return FF_DONE;
            this->state = state_recv_path;
            break;

        case state_recv_path:
            if(!get_protocol_string(&conn->in_buffer, &path))
                return FF_AGAIN;
            if(!is_path_safe(path))
                return FF_ERROR;
            this->state = state_item_done;
            break;

        case state_item_done:
            this->file_list.push_back(path);
            --this->size;
            if(this->size == 0)
            {
                this->task = new get_hash_task(conn->processor.project_name, this->file_list);
                this->task_owner = false;
                g_task_sched->submit(this->task);
                conn->processor.set_event(FF_ON_TIMEOUT);
                this->state = state_wait_bg_task;
                return FF_AGAIN;
            }
            this->state = state_recv_path;
            break;

        case state_wait_bg_task:
            if(!g_task_sched->checkout(this->task))
                return FF_AGAIN;
            this->task_owner = true;
            if(!this->task->is_finished())
                return FF_ERROR;
            for(iter = this->task->sha1_list.begin();
                iter != this->task->sha1_list.end(); ++iter)
            {
                if(*iter)
                    conn->out_buffer.push_back(*iter, 20);
                else
                    return FF_ERROR;
            }
            return FF_DONE;
        }
    }
}

/**
 *
 * [3] get_signature
 *
 * 描述：获取文件rsync签名
 * 参数：List<文件相对路径（String）>
 * 返回：List<rsync签名（var）>
 *
 */

get_sig_task::get_sig_task(const std::string &prj, const std::string &path)
{
    this->file_path = path;
    this->project_name = prj;
    this->finished = false;
    this->sig_file = NULL;
}

get_sig_task::~get_sig_task()
{
    if(this->sig_file)
        fclose(this->sig_file);
}

void get_sig_task::run()
{
    if(this->is_canceled())
        return;
    this->sig_file = ffstorage::rsync_sig(this->project_name, this->file_path);
    this->finished = true;
}

bool get_sig_task::is_finished()
{
    return this->finished;
}

get_signature::get_signature()
{
    this->state = state_recv_size;
    this->task = NULL;
    this->task_owner = true;
}

get_signature::~get_signature()
{
    if(this->task)
    {
        if(this->task_owner)
            delete this->task;
        else
            g_task_sched->cancel(this->task);
    }
}

int get_signature::update(connection *conn)
{
    char hdr[2] = {2, 0};
    uint32_t net_size;
    uint64_t u64_net;
    std::string path;
    char buffer[1024];
    size_t n;
    uint64_t count;

    if(conn->processor.project_name.empty())
        return FF_ERROR;
    while(1)
    {
        switch(this->state)
        {
        case state_recv_size:
            if(!get_protocol_uint32(&conn->in_buffer, &this->size))
                return FF_AGAIN;
            net_size = hton32(this->size);
            conn->out_buffer.push_back(hdr, 2);
            conn->out_buffer.push_back(&net_size, 4);
            if(this->size == 0)
                return FF_DONE;
            this->state = state_recv_path;
            break;

        case state_recv_path:
            if(!get_protocol_string(&conn->in_buffer, &path))
                return FF_AGAIN;
            if(!is_path_safe(path))
                return FF_ERROR;
            this->state = state_item_done;
            break;

        case state_item_done:
            --this->size;
            this->task = new get_sig_task(conn->processor.project_name, path);
            this->task_owner = false;
            g_task_sched->submit(this->task);
            conn->processor.set_event(FF_ON_TIMEOUT);
            this->state = state_wait_bg_task;
            break;

        case state_wait_bg_task:
            if(!g_task_sched->checkout(this->task))
                return FF_AGAIN;
            this->task_owner = true;
            if(!this->task->is_finished())
                return FF_ERROR;
            if(this->task->sig_file == NULL)
                return FF_ERROR;
            count = get_file_size(this->task->sig_file);
            u64_net = hton64(count);
            conn->out_buffer.push_back(&u64_net, 8);
            while((n = fread(buffer, 1, sizeof(buffer), this->task->sig_file)) > 0)
            {
                conn->out_buffer.push_back(buffer, n);
                count -= n;
            }
            delete this->task;
            this->task = NULL;
            if(count)
                return FF_ERROR;
            if(this->size == 0)
                return FF_DONE;
            else
            {
                conn->processor.set_event(FF_ON_READ);
                this->state = state_recv_path;
            }
            break;
        }
    }
}

/**
 *
 * [4] send_delta
 *
 * 描述：发送差异数据
 * 参数：List<文件相对路径（String）；差异数据（var）>
 *
 */

send_delta::send_delta()
{
    this->state = state_recv_size;
    this->file_fd = -1;
    this->index = 0;
}

send_delta::~send_delta()
{
    if(this->file_fd != -1)
        close(this->file_fd);
}

int send_delta::update(connection *conn)
{
    file_info info;

    if(conn->processor.project_name.empty())
        return FF_ERROR;
    while(1)
    {
        switch(this->state)
        {
        case state_recv_size:
            if(!get_protocol_uint32(&conn->in_buffer, &this->size))
                return FF_AGAIN;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->index = 0;
            this->file_list.clear();
            this->state = state_recv_path;
            break;

        case state_recv_path:
            if(!get_protocol_string(&conn->in_buffer, &this->path))
                return FF_AGAIN;
            if(!is_path_safe(this->path))
                return FF_ERROR;

            info.path = this->path;
            info.type = 'f';
            this->file_list.push_back(info);
            this->state = state_recv_data_size;
            break;

        case state_recv_data_size:
            if(!get_protocol_uint64(&conn->in_buffer, &this->data_size))
                return FF_AGAIN;
            this->file_fd = ffstorage::begin_delta(conn->processor.project_name, index);
            if(this->file_fd == -1)
                return FF_ERROR;
            this->state = state_recv_data;
            break;

        case state_recv_data:
            while(this->data_size > 0)
            {
                char buffer[1024];
                size_t size = sizeof(buffer);

                if(size > this->data_size)
                    size = this->data_size;
                size = conn->in_buffer.get(buffer, 0, size);
                conn->in_buffer.pop_front(size);
                if(size == 0)
                    return FF_AGAIN;
                if(write(this->file_fd, buffer, size) != (ssize_t)size)
                    return FF_ERROR;
                this->data_size -= size;
            }
            if(close(this->file_fd) == -1)
            {
                this->file_fd = -1;
                return FF_ERROR;
            }
            this->file_fd = -1;
            if(ffstorage::end_delta(conn->processor.project_name, this->path, index)
                    == false)
                return FF_ERROR;
            this->state = state_item_done;
            break;

        case state_item_done:
            ++this->index;
            --this->size;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                bool ok;

                ok = ffstorage::write_patch_list(
                            conn->processor.project_name, this->file_list);
                if(!ok)
                    return FF_ERROR;
                conn->processor.patch_list = this->file_list;
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->state = state_recv_path;
            break;
        }
    }
    return FF_DONE;
}

/**
 *
 * [5] send_deletion
 *
 * 描述：发送（-）文件列表
 * 参数：List<文件相对路径（String）>
 *
 */

send_deletion::send_deletion()
{
    this->state = state_recv_size;
}

send_deletion::~send_deletion()
{
}

int send_deletion::update(connection *conn)
{
    std::string path;
    file_info info;

    if(conn->processor.project_name.empty())
        return FF_ERROR;
    while(1)
    {
        switch(this->state)
        {
        case state_recv_size:
            if(!get_protocol_uint32(&conn->in_buffer, &this->size))
                return FF_AGAIN;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->state = state_recv_path;
            break;

        case state_recv_path:
            if(!get_protocol_string(&conn->in_buffer, &path))
                return FF_AGAIN;
            if(!is_path_safe(path))
                return FF_ERROR;
            this->state = state_item_done;
            break;

        case state_item_done:
            info.path = path;
            info.type = ffstorage::get_file_type(conn->processor.project_name, path);
            this->file_list.push_back(info);
            --this->size;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                bool ok;

                ok = ffstorage::write_del_list(conn->processor.project_name, this->file_list);
                if(!ok)
                    return FF_ERROR;
                conn->processor.deletion_list = this->file_list;
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->state = state_recv_path;
            break;
        }
    }
    return FF_DONE;
}

/**
 *
 * [6] send_addition
 *
 * 描述：发送（+）文件列表及其数据（如果是普通文件的话）
 * 参数：List<文件相对路径（String）；文件类型（char）；[文件数据（var）]>
 *
 */

send_addition::send_addition()
{
    this->state = state_recv_size;
    this->file_fd = -1;
}

send_addition::~send_addition()
{
    if(this->file_fd != -1)
        close(this->file_fd);
}

int send_addition::update(connection *conn)
{
    file_info info;

    if(conn->processor.project_name.empty())
        return FF_ERROR;
    while(1)
    {
        switch(this->state)
        {
        case state_recv_size:
            if(!get_protocol_uint32(&conn->in_buffer, &this->size))
                return FF_AGAIN;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->file_list.clear();
            this->index = 0;
            this->state = state_recv_path;
            break;

        case state_recv_path:
            if(!get_protocol_string(&conn->in_buffer, &this->path))
                return FF_AGAIN;
            if(!is_path_safe(this->path))
                return FF_ERROR;
            this->state = state_recv_type;
            break;

        case state_recv_type:
            if(!get_protocol_char(&conn->in_buffer, &this->type))
                return FF_AGAIN;
            fprintf(stderr, "[dump] path=%s type=%c\n", this->path.c_str(), this->type);
            info.path = this->path;
            info.type = this->type;
            this->file_list.push_back(info);
            if(this->type == 'd')
                this->state = state_item_done;
            else if(this->type == 'f')
                this->state = state_recv_data_size;
            else
                return FF_ERROR;
            break;

        case state_recv_data_size:
            if(!get_protocol_uint64(&conn->in_buffer, &this->data_size))
                return FF_AGAIN;
            this->file_fd = ffstorage::begin_add(conn->processor.project_name, this->index);
            if(this->file_fd == -1)
                return FF_ERROR;
            this->state = state_recv_data;
            break;

        case state_recv_data:
            while(this->data_size > 0)
            {
                char buffer[1024];
                size_t size = sizeof(buffer);

                if(size > this->data_size)
                    size = this->data_size;
                size = conn->in_buffer.get(buffer, 0, size);
                conn->in_buffer.pop_front(size);
                if(size == 0)
                    return FF_AGAIN;
                if(write(this->file_fd, buffer, size) != (ssize_t)size)
                    return FF_ERROR;
                this->data_size -= size;
            }
            if(close(this->file_fd) == -1)
            {
                this->file_fd = -1;
                return FF_ERROR;
            }
            this->file_fd = -1;
            ffstorage::end_add(conn->processor.project_name, this->path);
            this->state = state_item_done;
            break;

        case state_item_done:
            ++this->index;
            --this->size;
            if(this->size == 0)
            {
                char hdr[2] = {2, 0};
                bool ok;

                ok = ffstorage::write_add_list(conn->processor.project_name, this->file_list);
                if(!ok)
                    return FF_ERROR;
                conn->processor.addition_list = this->file_list;
                conn->out_buffer.push_back(hdr, 2);
                return FF_DONE;
            }
            this->state = state_recv_path;
            break;
        }
    }
    return FF_DONE;
}

/**
 *
 * [7] finish_backup
 *
 * 描述：通知服务端可以结束备份了，客户端在接收到服务端的确认后可以认为备份已经成功完成，
 *      并且客户端应该主动关闭连接
 *
 */

finish_bak_task::finish_bak_task(
        const std::string &prj, uint64_t task_id,
        const std::list<file_info> &patch_list,
        const std::list<file_info> &deletion_list,
        const std::list<file_info> &addition_list)
{
    this->project_name = prj;
    this->task_id = task_id;
    this->patch_list = patch_list;
    this->deletion_list = deletion_list;
    this->addition_list = addition_list;
    this->finished = false;
}

finish_bak_task::~finish_bak_task()
{
}

void finish_bak_task::run()
{
    size_t id;
    std::string history_path;
    std::list<file_info>::iterator iter;
    size_t index;

    if(!ff_trylock(this->project_name, this->task_id))
        return;

    id = ffstorage::get_history_qty(this->project_name);
    history_path = project_name + "/history/" + size2string(id);
    if(rename((project_name + "/cache").c_str(), history_path.c_str()) < 0)
        goto fail;

    //将 patch 后的文件移动到 current 目录中
    index = 0;
    for(iter = this->patch_list.begin(); iter != this->patch_list.end(); ++iter)
    {
        int ret;

        ret = rename((history_path + "/rc/" + size2string(index)).c_str(),
               (project_name + "/current/" + iter->path).c_str());
        if(ret == -1)
            goto fail;
        ++index;
    }
    rmdir((history_path + "/rc").c_str());
    //递归删除列表中的文件
    for(iter = this->deletion_list.begin(); iter != this->deletion_list.end(); ++iter)
        rm_recursive(project_name + "/current/" + iter->path);
    //将新增的文件复制到相应目录下
    index = 0;
    for(iter = this->addition_list.begin(); iter != this->addition_list.end(); ++iter)
    {
        bool ok;

        if(iter->type == 'f')
            ok = link_or_copy(history_path + "/" + size2string(index),
                      project_name + "/current/" + iter->path);
        else if(iter->type == 'd')
            ok = (0 == mkdir((project_name + "/current/" + iter->path).c_str(), 0775));
        else
            ok = false;
        if(!ok)
            goto fail;
        ++index;
    }
    if(ffstorage::write_info(project_name, id) == false)
        goto fail;
    this->finished = true;

fail:
    ff_unlock(this->project_name, this->task_id);
}

bool finish_bak_task::is_finished()
{
    return this->finished;
}

finish_backup::finish_backup()
{
    this->task = NULL;
    this->task_owner = true;
}

finish_backup::~finish_backup()
{
    if(this->task)
    {
        if(this->task_owner)
            delete this->task;
        else
            g_task_sched->cancel(this->task);
    }
}

int finish_backup::update(connection *conn)
{
    char hdr[2] = {2, 0};

    if(conn->processor.project_name.empty())
        return FF_ERROR;

    if(this->task == NULL)
    {
        this->task = new finish_bak_task(
                    conn->processor.project_name,
                    conn->processor.task_id,
                    conn->processor.patch_list,
                    conn->processor.deletion_list,
                    conn->processor.addition_list);
        this->task_owner = false;
        g_task_sched->submit(this->task);
        conn->processor.set_event(FF_ON_TIMEOUT);
        return FF_AGAIN;
    }

    if(!g_task_sched->checkout(this->task))
        return FF_AGAIN;
    this->task_owner = true;
    if(!this->task->is_finished())
        return FF_ERROR;
    conn->out_buffer.push_back(hdr, 2);
    return FF_DONE;
}

/**
 *
 * [8] client_get_prj
 *
 * 描述：客户端获取可恢复的项目名称列表
 * 返回：List<项目名称(String)>
 *
 */

client_get_prj::client_get_prj()
{
}

client_get_prj::~client_get_prj()
{
}

int client_get_prj::update(connection *conn)
{
    char hdr[2] = {2, 0};
    std::list<std::string> prj_list;
    std::list<std::string>::iterator iter;
    uint32_t list_size;

    prj_list = ffstorage::get_project_list();
    conn->out_buffer.push_back(hdr, 2);
    list_size = hton32(prj_list.size());
    conn->out_buffer.push_back(&list_size, 4);
    for(iter = prj_list.begin(); iter != prj_list.end(); ++iter)
    {
        conn->out_buffer.push_back(iter->c_str(), iter->size() + 1);
    }
    return FF_DONE;
}

/**
 *
 * [9] client_get_time_line
 *
 * 描述：客户端获取指定项目的历史记录
 * 参数：项目名称(String)
 * 返回：List<备份序号(uint32_t)；备份完成时间(uint32_t)>
 * 说明：备份序号是唯一标识一次备份的标识，备份完成时间是UNIX时间戳，单位是秒
 *
 */

client_get_time_line::client_get_time_line()
{
}

client_get_time_line::~client_get_time_line()
{
}

int client_get_time_line::update(connection *conn)
{
    std::string prj_name;
    std::list<uint32_t> time_line;
    std::list<uint32_t>::iterator iter;
    uint32_t index;
    uint32_t list_size;
    char hdr[2] = {2, 0};

    if(!get_protocol_string(&conn->in_buffer, &prj_name))
        return FF_AGAIN;
    if(!is_project_name_safe(prj_name.c_str()))
        return FF_ERROR;
    time_line = ffstorage::get_project_time_line(prj_name);
    list_size = hton32(time_line.size());
    conn->out_buffer.push_back(hdr, 2);
    conn->out_buffer.push_back(&list_size, 4);
    for(index = 0, iter = time_line.begin(); iter != time_line.end(); ++iter, ++index)
    {
        uint32_t tmp;

        tmp = hton32(index);
        conn->out_buffer.push_back(&tmp, 4);
        tmp = *iter;
        conn->out_buffer.push_back(&tmp, 4);
    }
    return FF_DONE;
}

/**
 *
 * [10] client_restore
 *
 * 描述：客户端请求恢复数据
 * 参数：项目名称(String)；备份序号(uint32_t)
 * 返回：List<文件路径(String)；文件类型(char)；[文件数据(var)]>
 * 说明：文件路径是相对于项目的备份目录的相对路径，
 *      文件类型只有两种（f-普通文件、d-目录），目录没有文件数据这一项
 *
 */

client_restore_task::client_restore_task(const std::string &prj, uint32_t id,
                                         uint64_t task_id)
{
    this->prj      = prj;
    this->id       = id;
    this->task_id  = task_id;
    this->finished = false;
}

client_restore_task::~client_restore_task()
{
}

bool client_restore_task::is_finished()
{
    return this->finished;
}

void client_restore_task::run()
{
    if(!ff_trylock(this->prj, this->task_id))
        return;
    this->base_path = ffstorage::begin_restore(this->prj, this->id, &this->file_list);
    if(!this->base_path.empty())
        this->finished = true;
    ff_unlock(this->prj, this->task_id);
}

client_restore::client_restore()
{
    this->state      = state_recv_prj;
    this->task       = NULL;
    this->task_owner = true;
    this->fd         = -1;
}

client_restore::~client_restore()
{
    if(this->task)
    {
        if(this->task_owner)
            delete this->task;
        else
            g_task_sched->cancel(this->task);
    }
    if(this->fd >= 0)
        close(this->fd);
}

int client_restore::update(connection *conn)
{
    char hdr[2] = {2, 0};
    uint32_t list_size;
    file_info *info;
    uint64_t task_id;

    while(1)
    {
        switch(this->state)
        {
        case state_recv_prj:
            if(!get_protocol_string(&conn->in_buffer, &this->prj))
                return FF_AGAIN;
            if(!is_project_name_safe(this->prj.c_str()))
                return FF_ERROR;
            task_id = random();
            if(!ff_trylock(this->prj, task_id))
                return FF_ERROR;
            conn->processor.project_name = this->prj;
            conn->processor.task_id = task_id;
            this->state = state_recv_id;
            break;

        case state_recv_id:
            if(!get_protocol_uint32(&conn->in_buffer, &this->id))
                return FF_AGAIN;
            this->task = new client_restore_task(this->prj, this->id,
                                                 conn->processor.task_id);
            this->task_owner = false;
            g_task_sched->submit(this->task);
            conn->processor.set_event(FF_ON_TIMEOUT);
            this->state = state_wait;
            break;

        case state_wait:
            if(!g_task_sched->checkout(this->task))
                return FF_AGAIN;
            this->task_owner = true;
            if(!this->task->is_finished())
                return FF_ERROR;
            conn->out_buffer.push_back(hdr, 2);
            list_size = hton32(this->task->file_list.size());
            conn->out_buffer.push_back(&list_size, 4);
            conn->processor.set_event(FF_ON_WRITE);
            this->state = state_response;
            break;

        case state_response:
            if(this->task->file_list.empty())
            {
                ffstorage::end_restore(this->prj);
                return FF_DONE;
            }
            info = &this->task->file_list.front();
            conn->out_buffer.push_back(info->path.c_str(), info->path.size() + 1);
            conn->out_buffer.push_back(&info->type, 1);
            if(info->type == 'f')
            {
                uint64_t u64;
                struct stat buf;
                std::string real_path = this->task->base_path + "/" + info->path;

                this->fd = open(real_path.c_str(), O_RDONLY);
                if(this->fd < 0)
                    return FF_ERROR;
                if(fstat(this->fd, &buf) < 0)
                    return FF_ERROR;
                this->file_size = buf.st_size;
                u64 = hton64(this->file_size);
                conn->out_buffer.push_back(&u64, 8);
                if(this->file_size == 0)
                    this->state = state_item_done;
                else
                    this->state = state_send_file;
            }
            else
                this->state = state_item_done;
            break;

        case state_send_file:
            do
            {
                char buffer[1024];
                size_t n = sizeof(buffer);
                ssize_t ret;

                if(n > this->file_size)
                    n = this->file_size;
                ret = read(this->fd, buffer, n);
                if(ret < 0 || (size_t)ret != n)
                    return FF_ERROR;
                conn->out_buffer.push_back(buffer, n);
                this->file_size -= n;
                if(this->file_size == 0)
                    this->state = state_item_done;
                else
                    return FF_AGAIN;
            }while(0);
            break;

        case state_item_done:
            if(this->fd >= 0)
            {
                close(this->fd);
                this->fd = -1;
            }
            this->task->file_list.pop_front();
            this->state = state_response;
            break;
        }
    }
}

ffprotocol::ffprotocol()
{
    this->event = FF_ON_READ;
    this->task_id = 0;
}

ffprotocol::~ffprotocol()
{
    this->reset();
}

//执行队列中的任务
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
    //实际上，在当前的实现中，队列中最多只有一个元素
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
            case 0x01:
                task.cmd = new start_backup();
                task.initial_event = FF_ON_READ;
                break;
            case 0x02:
                task.cmd = new get_hash();
                task.initial_event = FF_ON_READ;
                break;
            case 0x03:
                task.cmd = new get_signature();
                task.initial_event = FF_ON_READ;
                break;
            case 0x04:
                task.cmd = new send_delta();
                task.initial_event = FF_ON_READ;
                break;
            case 0x05:
                task.cmd = new send_deletion();
                task.initial_event = FF_ON_READ;
                break;
            case 0x06:
                task.cmd = new send_addition();
                task.initial_event = FF_ON_READ;
                break;
            case 0x07:
                task.cmd = new finish_backup();
                task.initial_event = FF_ON_WRITE;
                break;
            case 0x08:
                task.cmd = new client_get_prj();
                task.initial_event = FF_ON_WRITE;
                break;
            case 0x09:
                task.cmd = new client_get_time_line();
                task.initial_event = FF_ON_READ;
                break;
            case 0x0A:
                task.cmd = new client_restore();
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
    return (this->event & FF_ON_READ);
}

bool ffprotocol::wait_for_writable()
{
    return (this->event & FF_ON_WRITE);
}

bool ffprotocol::wait_for_timeout()
{
    return (this->event & FF_ON_TIMEOUT);
}

void ffprotocol::set_event(int ev)
{
    this->event = ev;
}

void ffprotocol::reset()
{
    ff_unlock(this->project_name, this->task_id);
    this->event = FF_ON_READ;
    this->task_id = 0;
    this->project_name.clear();
    this->patch_list.clear();
    this->deletion_list.clear();
    this->addition_list.clear();
    while(!this->task_queue.empty())
    {
        fftask task = this->task_queue.front();
        if(task.cmd)
            delete task.cmd;
        this->task_queue.pop();
    }
}
