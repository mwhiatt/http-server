#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <cerrno>
#include <signal.h>
#include <sys/wait.h>

int QueueLength = 5;
int port;
pthread_mutex_t mutex;
char pass[] = "amFja2phbWVzZGF2aWQ6Y21vbm1hbg==";
//username: jackjamesdavid
//password: cmonman
//guz

void processDocRequest(int socket);
void processRequestThread(int socket);
bool endsWith(char *str1, char *str2);
void poolSlave(int socket);

extern "C" void sigIntHandler(int sig) {
  if (sig == SIGCHLD) {
    pid_t pid = waitpid(-1, NULL, WNOHANG);
  }
}


int main(int argc, char ** argv) {
   // Add your HTTP implementation here
  bool flags = false;
  char flag = 0;
  if (argc < 2 || argc > 3) {
    printf("Improper Usage.\nTry: myhttpd [-f | -t | -p] <port>\n");
    printf("Flags:\n");
    printf("\t-f: Create a new process for each request.\n");
    printf("\t-t: Create a new thread for each request.\n");
    printf("\t-p: Create a pool of threads to manage requests.\n");
    printf("\tNo flag: Creates iterative server.\n");
    printf("Example: \"myhttpd -t 1047\" runs the server on port 1047 \n\t ");
    printf("and creates a new thread for every request.\n");
    exit(-1);
  } else if (argc == 3) {
    flags = true;
    flag = argv[1][1];
    port = atoi(argv[2]);
  } else {
    port = atoi(argv[1]);
  }
  //printf("port: %d\n", port);
  //printf("flag: %c\n", flag);
  // Set the IP address and port for this server
  struct sockaddr_in serverIPAddress; 
  memset( &serverIPAddress, 0, sizeof(serverIPAddress) );
  serverIPAddress.sin_family = AF_INET;
  serverIPAddress.sin_addr.s_addr = INADDR_ANY;
  serverIPAddress.sin_port = htons((u_short) port);

  // Allocate a socket
  int masterSocket =  socket(PF_INET, SOCK_STREAM, 0);
  if ( masterSocket < 0) {
    perror("socket");
    exit( -1 );
  }
  // Set socket options to reuse port. Otherwise we will
  // have to wait about 2 minutes before reusing the sae port number
  int optval = 1; 
  int err = setsockopt(masterSocket, SOL_SOCKET, SO_REUSEADDR, 
           (char *) &optval, sizeof( int ) );

  // Bind the socket to the IP address and port
  int error = bind( masterSocket,
        (struct sockaddr *)&serverIPAddress,
        sizeof(serverIPAddress) );
  if ( error ) {
    perror("bind");
    exit( -1 );
  }
  //printf("50\n");
  // Put socket in listening mode and set the 
  // size of the queue of unprocessed connections
  error = listen( masterSocket, QueueLength);
  if ( error ) {
    perror("listen");
    exit( -1 );
  }

  if (flag == 'p') {
    pthread_t tid[5];
    pthread_mutex_init(&mutex, NULL);
    for (int i = 0; i < 5; i++) {
      pthread_create(&tid[i], NULL, (void *(*)(void *))poolSlave, (void *)masterSocket);
    }
    pthread_join(tid[0], NULL);
  } else {
    while ( 1 ) {
      // Accept incoming connections
      struct sockaddr_in clientIPAddress;
      int alen = sizeof( clientIPAddress );
      int slaveSocket = accept( masterSocket,
              (struct sockaddr *)&clientIPAddress,
               (socklen_t*)&alen);

      if ( slaveSocket == -1 && errno == EINTR ) {
        continue;
      }
      if (slaveSocket < 0) {
        perror("accept");
        exit(-1);
      }
      if (!flags) {
        processDocRequest( slaveSocket ); //process request
        close( slaveSocket ); //close socket
      }

      if (flag == 't') { //create thread for every connection
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); //detaches automatically
        pthread_create(&t, &attr, (void * (*) (void *)) processRequestThread, (void *) slaveSocket);
        //closes in function per lab5 slides
      }

      if (flag == 'f') { //create process for every connection
        struct sigaction sa;
        sa.sa_handler = sigIntHandler; //shell project zombie code
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        pid_t slave = fork();
        if (slave == 0) {
          processDocRequest(slaveSocket);
          close(slaveSocket);
          exit(EXIT_SUCCESS);
        }
        if (sigaction(SIGCHLD, &sa, NULL)) {
          perror("sigaction");
          exit(-1);
        }
        close(slaveSocket);
      }
    }
  }

}

void processDocRequest( int fd ) {
  // Buffer used to store the name received from the client
  const int MaxWord = 4096;
  char word[ MaxWord + 1 ];
  int length = 0;
  int n;
  char path[MaxWord + 1];

  // Send prompt: from daytime
  //const char * prompt = "\nType your name:";
  //write( fd, prompt, strlen( prompt ) );

  // Currently character read
  unsigned char newChar;

  // Last character read
  unsigned char lastChar = 0;

  //
  // The client should send GET <sp><Document><sp>HTTP/1.0<crlf>
  // Read the name of the client character by character until a
  // <CR><LF> is found.
  //

  bool get = false;
  bool crlf = false;
  bool psw = false;
  bool auth = false;
  bool basic = false;
  char curr_pass[256];
  curr_pass[0] = '\0';
  int check = 0;
  //explicit_bzero(curr_pass, 256);

  while ((n = read(fd, &newChar, sizeof(newChar))) > 0 ) {

    if ( newChar == ' ' ) {
      //printf("%c", newChar);
      //request has spaces in a bunch of spots, particularly after the get
      if (strncmp("GET", word, 3) == 0) {
        get = true; //GET found
        memset(word, 0, MaxWord); //same as memset but skips having to tell it to put in /0's
        length = 0;
      } else if (strncmp("Basic", word, 5) == 0 && auth) {
        basic = true;
        memset(word, 0, MaxWord);
        length = 0;
        auth = false;
      } else if (strncmp("Authorization", word, 13) == 0) {
        memset(word, 0, MaxWord); //clear auth out to work with our earlier structure
        length = 0;
        auth = true;
      } else if (get) { //already found the GET and there's a space so we're at end of document
        word[length] = '\0'; //null terminate
        get = false;
        strcpy(path, word); //2. get document path
      } else {
        auth = false;
        basic = false;
      }
    } else if(newChar == '\n' && lastChar == '\r') { //end of important stuff
      if (basic) {
        printf("in basic\n");
        if (strlen(curr_pass) == 0) {
          strncpy(curr_pass, word, strlen(pass));
          psw = true;
          check = strcmp(pass, curr_pass);
        }
        basic = false;
      }
      memset(word, 0, MaxWord);
      length = 0;
      if (crlf) {
        break; //looking for a double crlf
      }
      crlf = true;
    } else {
      lastChar = newChar;
      if (newChar != '\r') {
        crlf = false;
      }
      word[length] = newChar;
      length++;
    }
  }
  if (strcmp(path, "/") == 0) {
    sprintf(path, "/index.html");
  }
  printf("Input path: %s\n", path); //check inputted subpath 


  char cwd[256];
  getcwd(cwd, 256);
  char expanded[MaxWord + 1];
  if (strncmp("/icons", path, sizeof("/icons")) == 0) {
    sprintf(expanded, "%s/http-root-dir/%s", cwd, path);
  } else if(strncmp("/htdocs", path, sizeof("/htdocs")) == 0) {
    sprintf(expanded, "%s/http-root-dir/%s", cwd, path);
  } else {
    sprintf(expanded, "%s/http-root-dir/htdocs%s", cwd, path);
  }

  int exp = strlen(expanded);
  int toofar = strlen(cwd) + 13;
  if (exp < toofar) {
    sprintf(expanded, "%s/http-root-dir/index.html", cwd);
  }

  if (!psw || check != 0) {
    printf("authenticate\n");
    printf("attempted password: %s\n", curr_pass);
    printf("actual: %s\n", pass);
    write(fd, "HTTP/1.1 401 Unauthorized\r\n", 27);
    printf("HTTP/1.1 401 Unauthorized\r\n");
    write(fd, "WWW-Authenticate: Basic realm=great_cs252_realm\r\n\r\n", 51);
    printf("WWW-Authenticate: Basic realm=great_cs252_realm\r\n\r\n");
  } else {
    //5. determine content type
    char contentType[16];
    if (endsWith(expanded, ".html") || endsWith(expanded, ".html/")) {
      strcpy(contentType, "text/html");
    } else if (endsWith(expanded, ".gif") || endsWith(expanded, ".gif/")) {
      strcpy(contentType, "image/gif");
    } else if (endsWith(expanded, ".svg")) {
      strcpy(contentType, "image/svg+xml");
    } else if (endsWith(expanded, ".css")) {
      strcpy(contentType, "text/css");
    } else if (endsWith(expanded, ".png")) {
      strcpy(contentType, "image/png");
    } else if (endsWith(expanded, ".jpeg") || endsWith(expanded, ".jpg")) {
      strcpy(contentType, "image/jpeg");
    } else {
      strcpy(contentType, "text/plain");
    }
    printf("expanded filepath: %s\n", expanded); //check filepath
    int newfd = open(expanded, O_RDWR, O_APPEND);
    if ( newfd < 0) {
      perror("open");
      //send 404
      write(fd, "HTTP/1.0 404FileNotFound\r\n", 26);
      write(fd, "Server: CS 25200 Lab5\r\n", 23);
      write(fd, "Content-type: ", 14);
      write(fd, contentType, strlen(contentType));
      write(fd, "File not Found", 14);
    } else { //7. send HTTP reply header
      write(fd, "HTTP/1.1 200 Document follows\r\n", 31);
      printf("HTTP/1.1 200 Document follows\r\n");
      write(fd, "Server: CS 252 lab5\r\n", 21);
      printf("Server: CS 252 lab5\r\n");
      write(fd, "Content-type: ", 14);
      printf("Content-type: ");
      write(fd, contentType, strlen(contentType));
      printf("%s", contentType);
      write(fd, "\r\n\r\n", 4); //double crlf
      printf("\r\n\r\n");
      //content
      char content[1048576]; //1048576
      int sentry;
      while(sentry = read(newfd, content, 1048576)) {
        printf("Content: %s\n", content);
        if (write(fd, content, sentry) != sentry) {
          perror("write");
          memset(content, 0, 1048576); //same as memset but don't have to specify the 0's
          break;
        }
      }
    }
    close(newfd);
  }
}

bool endsWith(char * str1, char * str2) {
  int start = strlen(str1) - strlen(str2);
  if (start < 0) {
    return false;
  } else {
    for (int i = 0; i < strlen(str2); i ++) {
      if (str1[start+i] != str2[i]) {
        return false;
      }
    }
    return true;
  }
}

void processRequestThread(int fd) {
  processDocRequest(fd);
  close(fd);
}

void poolSlave(int socket) {
  while (1) {
    struct sockaddr_in clientIPAddress;
    int alen = sizeof(clientIPAddress);
    pthread_mutex_lock(&mutex); //lock
    int slaveSocket = accept(socket, (struct sockaddr *)&clientIPAddress, (socklen_t *) &alen);
    pthread_mutex_unlock(&mutex); //unlock
    if (slaveSocket < 0) {
      perror("accept");
      exit(-1);
    }
    processDocRequest(slaveSocket);
    close(slaveSocket);
  }
}
