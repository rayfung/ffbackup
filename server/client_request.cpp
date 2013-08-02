#include "client_request.h"

client_request::client_request()
{
    this->version = -1;
    this->op = -1;
    this->common_header_ok = false;
}

client_request::~client_request()
{
}

int client_request::get_version() const
{
    return this->version;
}

int client_request::get_op() const
{
    return this->op;
}

enum client_request::result client_request::update_header(ffbuffer *request)
{
    unsigned char buf[2];
    size_t ret;

    if(this->common_header_ok)
        return client_request::OK;

    if(request->get_size() < 2)
        return client_request::AGAIN;

    ret = request->get(buf, 0, 2);
    if(ret != 2)
        return client_request::ERROR;

    this->version = buf[0];
    this->op = buf[1];
    this->common_header_ok = true;
    request->pop_front(2);
    return client_request::OK;
}
