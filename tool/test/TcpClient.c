#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<arpa/inet.h>

int main()
{
    //make socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        return -1;
    }

    //bind ip port
    struct sockaddr_in saddr;
    saddr.sin_family =  AF_INET;
    saddr.sin_port = htons(8888);
    inet_pton(AF_INET, "192.168.174.135", &saddr.sin_addr.s_addr);
    int ret = connect(fd, (struct sockaddr*)&saddr, sizeof(saddr));
    if (ret == -1)
    {
        perror("connect");
        return -1;
    }


    int number;
    //communication
    while (1)
    {
        //send
        char buff[1024];
        sprintf(buff, "hello world: %d \n", number++);
        send(fd, buff, strlen(buff)+1, 0);

        //recv
        memset(buff, 0, sizeof(buff));
        int len = recv(fd, buff, sizeof(buff), 0);
        if (len > 0)
        {
            printf("server: %s\n", buff);
        }else if (len == 0)
        {
            printf("Server Disconnect\n");
            break;
        }else
        {
            perror("recv");
            break;
        }
        sleep(1);
    }
    

    close(fd);

    return 0;   
}