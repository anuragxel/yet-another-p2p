----------------------------------------
p2p - Anurag Ghosh, 201302179
Made for Computer Networks Assignment 2
----------------------------------------

The server runs on the child process while the
the client runs on the parent. The client console
tries to establish the connection every second till
it reaches a server.

The client console takes the command as input, parses it
and sends it to the server which also parses it for 
it's own use. The server then respondes according to 
the commands. 

The commands FileDownload and FileUpload read the files 
to be uploaded/downloaded byte by byte and sends the 
packet size (<1024 bytes)  and the packet itself. 

The commands IndexGet and FileHash cause the server to 
send the whole file structure of the shared directory 
which is then processed by the client accoring to need,
depending on the flags as needed. It is a concious choice
made as i think servers should process as less as possible,
however this results sending more amount of data than that 
is actually needed.

The Hashing and Regex matching use the openssl/md5 and regex 
libraries respectively. All other dependencies are provided 
by the glibc.
