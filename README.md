# About
Server code for handling HTTP GET requests and serving the correct information back to the client. 

# Usage
In base directory: ./myhttpd [ -t | -f | -p] [port]
-t: spawn a thread for each incoming connection
-f: spawn a process for each incoming connection
-p: create a pool of threads to manage requests
