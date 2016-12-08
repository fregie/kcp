/*************************************************************************
	> File Name: test.c
	> Author: fregie
	> Mail: fregie@geewan.com
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<errno.h>

//define send and recv buf size
#define BUFSIZE 250*1024

//define action message
//change here to change action
#define ADD_USER "{\"act\":\"add_user\",\"token\":\"b88d9ad8eab2\",\"password\":\"geewantest123456789123456789123456789\",\
\"txquota\":10240000,\"expire\":\"2017/6/3 14:57:00\", \
\"up_limit\":0,\"up_burst\":512,\"down_limit\":256,\"down_burst\":512}"
#define DEL_USER "{\"act\":\"del_user\",\"token\":\"b88d9ad8eab2\"}"
#define SHOW_STAT "{\"act\":\"show_stat\"}"
char *msg_to_send = ADD_USER;

//define unix domain socket path
#define pmmanager "/tmp/GTS.sock"
#define pmapi "/tmp/pmapi"

int main(int argc, char** argv)
{
    char tx_buf[BUFSIZE];
    int pmapi_fd, ret;
    socklen_t len;
    struct sockaddr_un pmmanager_addr, pmapi_addr;
    
    //create pmmanager socket fd
    pmapi_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if(pmapi_fd == -1)
    {
    perror("cannot create pmapi fd.");
    }

    unlink(pmapi);
    //configure pmapi's addr
    memset(&pmapi_addr, 0, sizeof(pmapi_addr));
    pmapi_addr.sun_family = AF_UNIX;
    strncpy(pmapi_addr.sun_path, pmapi, sizeof(pmapi_addr.sun_path)-1);
    //bind pmapi_fd to pmapi_addr
    ret = bind(pmapi_fd, (struct sockaddr*)&pmapi_addr, sizeof(pmapi_addr));
    if(ret == -1)
    {
    perror("bind error.");
    }

    int sendBufSize;
    len = sizeof(sendBufSize);
    ret = getsockopt(pmapi_fd, SOL_SOCKET, SO_SNDBUF, &sendBufSize, &len);
    if(ret ==-1)
    {
        perror("getsocket error.");
    }
    printf("Before setsockopt, SO_SNDBUF-%d\n",sendBufSize); 
    sendBufSize = 512*1024;
    ret = setsockopt(pmapi_fd, SOL_SOCKET, SO_SNDBUF, &sendBufSize, len);
    if(ret == -1)
    {
        perror("setsockopt error.");
    }
    ret = getsockopt(pmapi_fd, SOL_SOCKET, SO_SNDBUF, &sendBufSize, &len);
    if(ret ==-1)
    {
        perror("getsocket error.");
    }
    printf("Set send buf successful, SO_SNDBUF-%d\n\n\n", sendBufSize); 

    //configure pmmanager's addr
    memset(&pmmanager_addr, 0, sizeof(pmmanager_addr));
    pmmanager_addr.sun_family = AF_UNIX;
    strncpy(pmmanager_addr.sun_path, pmmanager, sizeof(pmmanager_addr)-1);
    len = sizeof(pmmanager_addr);

    int sendSize = 0;
    int i;
    sendSize = sendto(pmapi_fd, msg_to_send, strlen(msg_to_send), 0, (struct sockaddr*)&pmmanager_addr, len);
    if(sendSize == -1)
    {
        perror("sendto error.");
    }
    printf("Send message to gts: %s\n\n\n", msg_to_send);
    char *buf = malloc(1000);
    int recvsize = recvfrom(pmapi_fd, buf, 1000, 0,(struct sockaddr*)&pmmanager_addr, &len);
    printf("msg:%s\n",buf);
}

