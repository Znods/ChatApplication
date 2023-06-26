#define  _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <pthread.h>

#define ADMIN_PORT 1337
#define CHAT_PORT "31337"

#define MAX_EVENTS 1000000
#define BUF_SIZE 500

static volatile int efd = 0;
static volatile int sfd = 0;
static volatile int servfd = 0;


#define XOR_KEY "0xDEADBEEF"

/*
Server Side
IO Multiplexing
*/

struct userlist{
    char *ip;
    char *msg;
    bool status;
}user[MAX_EVENTS];

struct adminlist{
    char *ip;
    bool status;
}admin[MAX_EVENTS];

const char *admin_username[MAX_EVENTS] = {"testuser", "testuser2", NULL};
const char *admin_password[MAX_EVENTS] = {"testpass", "testpass2", NULL};

static int blacklist_user(){
    return 0;
}

void xor_cipher(char *buffer, char *key){ // for secure comms between server and clients
    int keyLen = strlen(key);
    char tmp[BUF_SIZE + 1];
    memset(tmp, 0, BUF_SIZE + 1);
    strcpy(tmp, buffer);
    memset(buffer, 0, BUF_SIZE + 1);
    for(int i = 0; i < strlen(tmp); i++)
        buffer[i] = tmp[i] ^ key[i % keyLen];
}

unsigned int usersConnected(){
    unsigned int i = 0, nusers = 0;
    while(i < MAX_EVENTS){
        if(user[i].status) 
            nusers++;
        i++;
    }
    return nusers;
}

void broadcast(){
    int i;
    for(i = 0; i < MAX_EVENTS; i++){
        if(i != servfd && admin[i].ip == NULL && user[i].ip != NULL)
            send(i, "PING\r\n", 7, MSG_NOSIGNAL);
    }
}

void trim(char *str){
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

static int make_socket_non_blocking(int sockfd){
    int flags;

    // Get the current socket flags
    if ((flags = fcntl(sockfd, F_GETFL, 0)) == -1) {
        return -1;
    }

    // Set the socket to be non-blocking
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

static int fdgets(unsigned char *buffer, int bufferSize, int fd){
    int total = 0, got = 1;
        
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') {
        got = read(fd, buffer + total, 1); 
        total++; 
    }

    return got;
}

void *titleWriter(void *sock){
    int *thefd = (int *)sock;
    char string[38];
    while(1){
        memset(string, 0, 38);
        sprintf(string, "%c]0;Clients %u%c", '\033', usersConnected(), '\007');
        if(send(*thefd, string, strlen(string), MSG_NOSIGNAL) == -1) 
            return NULL;
        sleep(2);
    }
}

static bool find_login(char *buf, const char **logininfo){
    for(int i = 0; logininfo[i] != NULL; i++){
        if(strncmp(buf, logininfo[i], strlen(buf)) == 0){
            return true;
        }
    }
    return false;
}

void *readWorker(void *x){
    int *fd = (int *)x;
    char buffer[BUF_SIZE];
    char message1[BUF_SIZE];
    bool findlogin;
    int max_attempts = 0, done = 0;
    pthread_t thread;

    /* Login */
    while(max_attempts != 4){
        max_attempts++;
        send(*fd, "username: ", 11, MSG_NOSIGNAL);
        memset(buffer, 0, BUF_SIZE);
        fdgets(buffer, BUF_SIZE, *fd);
        trim(buffer);
        
        findlogin = find_login(buffer, admin_username);
        if(!findlogin) continue;
        
        send(*fd, "password: ", 11, MSG_NOSIGNAL);
        memset(buffer, 0, BUF_SIZE);
        fdgets(buffer, BUF_SIZE, *fd);
        trim(buffer);
        
        findlogin = find_login(buffer, admin_password);
        if(!findlogin) continue;
        else
            break;
    }

    if(max_attempts == 4){
        puts("Admin failed to connect!");
        send(*fd, "Failed, logging ip...\r\n", 24, MSG_NOSIGNAL);
        sleep(3);
        goto cleanup;
    }


    send(*fd, "\033[2J\r\f", 5, MSG_NOSIGNAL);
    send(*fd, "Welcome to Znods TCP Chat Application.\r\n", 41, MSG_NOSIGNAL);

    puts("Admin connected!");

    pthread_create(&thread, NULL, titleWriter, (void *)fd);

    memset(buffer, 0, BUF_SIZE);

    while(fdgets(buffer, BUF_SIZE, *fd) > 0){
        trim(buffer);
        printf("\033[1;31mADMIN \033[0m(\033[1;31m%s\033[0m) -> %s\n", admin[*fd].ip, buffer);

        send(*fd, "\r\033[0;31mroot\033[0m@\033[1;31mchat\033[0;31m#\033[1;31m>\033[0m ", 50, MSG_NOSIGNAL);

/* Commands */
        if(strncmp(buffer, ".logout", 8) == 0) goto cleanup;
        if(strncmp(buffer, "cls", 4) == 0){
            send(*fd, "\033[2J", 5, MSG_NOSIGNAL);
            memset(message1, 0, BUF_SIZE);
            sprintf(message1, "\r\033[0mClients Online: %d\r\n", usersConnected());
            send(*fd, message1, strlen(message1), MSG_NOSIGNAL);
            send(*fd, "\r\033[0;31mroot\033[0m@\033[1;31mchat\033[0;31m#\033[1;31m>\033[0m ", 50, MSG_NOSIGNAL);
        }
        if(strncmp(buffer, ".test", 5) == 0){
            for(int i = 0; i < MAX_EVENTS; i++){
                if(i != *fd)
                    send(i, "test message from server...\r\n", 30, MSG_NOSIGNAL); 
            }
        }
        if(strncmp(buffer, ".restart", 9) == 0){
            for(int i = 0; i < MAX_EVENTS; i++){
                if(i != *fd){
                    send(i, "/x06", 30, MSG_NOSIGNAL); 
                } 
            }
        }

        memset(buffer, 0, BUF_SIZE);
    }

cleanup:
    fprintf(stdout, "\033[1;31mADMIN\033[0m (\033[1;31m%s\033[0m) left the admin pannel.\n", admin[*fd].ip);
    admin[*fd].ip = NULL;
    admin[*fd].status = false;
    close(*fd);
    return NULL;
}

void *tcpListener(void *x){
    int cfd = 0;
    const int on = 1;
    struct sockaddr_in serv, cli;
    socklen_t cli_len;
    pthread_t thread;

    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_port = htons(ADMIN_PORT);
    serv.sin_addr.s_addr = INADDR_ANY;

    cli_len = sizeof(cli);


    if((servfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        perror("socket");

    if(setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0)
        perror("setsockopt");

    if(bind(servfd, (struct sockaddr *)&serv, sizeof(serv)) < 0)
        perror("bind");

    if(listen(servfd, 5) < 0)
        perror("listen");
    
    while(1){
        if((cfd = accept(servfd, (struct sockaddr *)&cli, &cli_len)) < 0)
            fprintf(stderr, "%s %s\n", inet_ntoa(cli.sin_addr), strerror(errno));

        admin[cfd].ip = inet_ntoa(cli.sin_addr);
        admin[cfd].status = true;
        
        fprintf(stdout, "\033[1;31mADMIN\033[0m (\033[1;31m%s\033[0m) attempting to connect.\n", admin[cfd].ip);

        /* Start Read Worker */
        pthread_create(&thread, NULL, readWorker, (void *)&cfd);
    }

}

static int create_and_bind(){
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int fd, s;
    const int on = 1;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    s = getaddrinfo(NULL, CHAT_PORT, &hints, &result);
    if (s != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        abort();
    }

    for(rp = result; rp != NULL; rp = rp->ai_next){
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd == -1)
            continue;

        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) == -1)
            abort();

        if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;                  /* Success */

        close(fd);
    }

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not bind\n");
        abort();
    }

    freeaddrinfo(result);           /* No longer needed */

    return fd;

}

void *epollEvent(void *x){
    /* Event Loop */
    struct epoll_event ev;
    struct epoll_event *ep_event;
    char buf[BUF_SIZE];
    char message1[BUF_SIZE];

    ep_event = calloc(MAX_EVENTS, sizeof ev);

    while(1){
        int nfds, i;

        // monitor read for readiness for reading
        nfds = epoll_wait(efd, ep_event, MAX_EVENTS, -1); // timout is infinite 

        // Some sockets are ready. Examine readfds
        for(i = 0; i < nfds; i++){
            if((ep_event[i].events & EPOLLERR) || (ep_event[i].events & EPOLLHUP) || (!(ep_event[i].events & EPOLLIN))){
                
                user[ep_event[i].data.fd].status = false;
                user[ep_event[i].data.fd].ip = NULL;
                //nusers--;
                close(ep_event[i].data.fd);
                continue;

            } else if(ep_event[i].data.fd == sfd){ // request for new connection
                    
                while(1){
                    struct sockaddr in_addr;
                    socklen_t in_len;
                    int newfd;
 
                    in_len = sizeof in_addr;

                    if((newfd = accept(sfd, &in_addr, &in_len)) == -1){
                        if((errno == EAGAIN) || (errno == EWOULDBLOCK))
                            break;
                        else {
                            fprintf(stderr, "accept\n");
                            break;
                        }
                    } 

                    if(make_socket_non_blocking(newfd) == -1){
                        user[newfd].ip = NULL;
                        close(newfd);
                        break;
                    }

                    /* Epoll Data */

                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = newfd;
                    
                    if(epoll_ctl(efd, EPOLL_CTL_ADD, newfd, &ev) == -1){
                        fprintf(stderr, "epoll_ctl\n");
                        user[newfd].ip = NULL;
                        close(newfd);
                        break;
                    }

                    user[newfd].status = true;
                    user[newfd].ip = inet_ntoa(((struct sockaddr_in *)&in_addr)->sin_addr);
                    //nusers++;

                    fprintf(stderr, "\033[1;36mCLIENT\033[0m:\033[1;36m%d\033[0m (\033[1;36m%s\033[0m) joined!\n", newfd, user[newfd].ip);

                        

                } /* Loop Breaks on EAGAIN || EWOULDBLOCK */

                continue;

            } else { /* Data from an existing user */
            
                int thefd = ep_event[i].data.fd, done = 0;
                struct userlist *clients = (struct userlist *)&(user[thefd]);

                clients->status = true;

                while(1){
                    ssize_t nbytes;

                    while(memset(buf, 0, sizeof buf) && (nbytes = fdgets(buf, sizeof buf, thefd)) > 0){
                        trim(buf);
                        if(strncmp(buf, "PONG", 5) == 0) { /* IRC Like Ping Pong */
                            if(send(thefd, "\n", 1, MSG_NOSIGNAL) == -1){ 
                                done = 1; 
                                break; 
                            }
                            clients->status = true;
                            continue;
                        }

                        fprintf(stdout, "\033[1;36mCLIENT\033[0m:\033[1;36m%d\033[0m (\033[1;36m%s\033[0m) -> %s\n", thefd, clients->ip, buf);

                    }     

                    if(nbytes == -1){
                        if (errno != EAGAIN){
                            done = 1;
                        }
                        break;
                    } else if(nbytes == 0){
                        done = 1;
                        break;
                    }                  

                }          
                
                if(done){
                    fprintf(stderr, "\033[1;36mCLIENT\033[0m:\033[1;36m%d\033[0m (\033[1;36m%s\033[0m) has left.\n", thefd, clients->ip);
                    clients->ip = NULL;
                    clients->status = false;
                    close(thefd);
                }
            
            }
            
        }
    }
    free(ep_event);
}


int main(int argc, char *argv[]){
    struct epoll_event ev;
    int ret;
    ssize_t nread;

    if(argc < 2){
        printf("usage: %s <thread_count>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("Starting chat server on port %s...\n", CHAT_PORT);

    int nthreads = atoi(argv[1]);

    /* create_and_bind chat server */

    sfd = create_and_bind(CHAT_PORT); // CHAT_PORT
    if(sfd == -1){
        fprintf(stderr, "Couldn't create and bind socket...\n");
        abort();
    }

    ret = make_socket_non_blocking(sfd);
    if(ret == -1){
        fprintf(stderr, "Failed to make socket non-blocking\n");
        abort();
    }

    if(listen(sfd, 5) == -1){
        fprintf(stderr, "%s 1\n", strerror(errno));
        abort();
    }

    if((efd = epoll_create1(0)) == -1){
        fprintf(stderr, "%s epoll1\n", strerror(errno));
        abort();
    }

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sfd;

    if(epoll_ctl(efd, EPOLL_CTL_ADD, sfd, &ev) == -1){
        fprintf(stderr, "%s ctl\n", strerror(errno));
        abort();
    }

    pthread_t thread[nthreads + 2];
    while(nthreads--){
        printf("starting epoll[%d]...\n", nthreads);
        pthread_create(&thread[nthreads + 1], NULL, epollEvent, NULL);
    }

    // start admin pannel
    printf("Starting admin pannel on port %d...\n", ADMIN_PORT);
    pthread_create(&thread[0], NULL, tcpListener, NULL);

    puts("Started!\n\n");

    while(1){
        broadcast();
        sleep(120);
    }

    close(sfd);

    return 0;
}