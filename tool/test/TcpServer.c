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
    saddr.sin_addr.s_addr = INADDR_ANY;
    //saddr.sin_addr.s_addr = htonl(inet_addr("192.168.174.135"));

    int ret = bind(fd, (struct sockaddr*)&saddr, sizeof(saddr));
    if (ret == -1)
    {
        perror("bind");
        return -1;
    }


    //set listen
    ret = listen(fd, 128);
    if (ret == -1)
    {
        perror("listen");
        return -1;
    }


    struct sockaddr_in caddr;
    int addrlen = sizeof(caddr);
    int cfd = accept(fd, (struct sockaddr*)&caddr, &addrlen);
    if (cfd == -1)
    {
        perror("accept");
        return -1;
    }
    
    
    printf("connect success");


    while (1)
    {
        char buff[1024];
        int len = recv(cfd, buff, sizeof(buff), 0);
        if (len > 0)
        {
            printf("client: %s\n", buff);
            send(cfd, buff, len, 0);
        }else if (len == 0)
        {
            printf("client Disconnect\n");
            break;
        }else
        {
            perror("recv");
            break;
        }
        
    }
    

    close(fd);
    close(cfd);

    return 0;   
}