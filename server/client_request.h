#ifndef CLIENT_REQUEST_H
#define CLIENT_REQUEST_H

#include "ffbuffer.h"

class client_request
{
public:
    enum result {OK, ERROR, AGAIN};
    client_request();
    ~client_request();
    int get_version() const;
    int get_op() const;
    virtual enum result update_header(ffbuffer *request);
    virtual enum result update_body(ffbuffer *request) = 0;

private:
    int version;
    int op;
    bool common_header_ok;
};

#endif
