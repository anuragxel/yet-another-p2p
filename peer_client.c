#include <stdio.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <regex.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RESET   "\033[0m"
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */

#define MAX_QUERY_SIZE 255
#define MAX_ARGS 10
#define LEN_PATH 256
#define LEN_MD5 MD5_DIGEST_LENGTH

struct file_struct {
	char file_name[1024];
	char file_time[1024];
	int file_size;
	char file_type[100];
	unsigned char file_md5[LEN_MD5 + 1];
};

typedef struct file_struct file_struct;

// Server
char server_send_data[1024];
char server_recv_data[1024];
file_struct server_fs[1024];
int server_file_count = 0;
char server_arg_string[MAX_QUERY_SIZE];
char server_query_arg_string[MAX_QUERY_SIZE];
char *server_args[MAX_ARGS];
int server_arg_size = 0;
char upload_string[1024];
int upload_flag;

//Client
char send_data[1024], recv_data[1024];
char recv_md5[LEN_MD5 + 1], calctd_md5[LEN_MD5 + 1];
char client_arg_string[MAX_QUERY_SIZE];
char input_arg_string[MAX_QUERY_SIZE];
char *arguments[MAX_ARGS];
int arg_size;
file_struct client_fs[1024];

void perr(char *x) {
	fprintf(stderr, BOLDRED "%s" RESET, x);
}

void pout(char *x) {
	fprintf(stdout, BOLDBLUE "%s" RESET, x);
}

// Sets socket blocking depending on
// boolean blocking.
int set_socket_blocking_enabled(int fd, int blocking)
{
   if (fd < 0) return -1;
   int flags = fcntl(fd, F_GETFL, 0);
   if (flags < 0) return -1;
   flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);
   return (fcntl(fd, F_SETFL, flags) == 0) ? 1 : -1;
}

//
//
int recv_wrapper(int sock, void *recv_data, int len, int flag) {
	int rv = -1;
	set_socket_blocking_enabled(sock,-1);
	while( (rv = recv(sock,recv_data,len,flag)) < 0 ) {
		//perr("[CLIENT] Chunk Not recieved.\n");
	}
	set_socket_blocking_enabled(sock,1);
	return rv;
}

int __debug_print_args(char **args, int size) {
	int j = 0;
	printf("DEBUG Size : %d ",size);
	printf("[ ");
	for(j=0;j<size;j++) {
		printf("\"%s\", ",args[j]);
	}
	printf(" ]\n");
}

// calculates the md5 hash of the
// file into the sum.
int calculate_md5(char *file_name, char *sum) {
	unsigned char c[MD5_DIGEST_LENGTH + 1];
	int i;
	FILE *file_desc = fopen (file_name, "rb");
	MD5_CTX md_context;
	int bytes;
	unsigned char data[1024];
	if (file_desc == NULL) {
	    perr("[MD5 Hasher] Can't be opened.\n");
	    return 0;
	}
	MD5_Init (&md_context);
	while ((bytes = fread (data, 1, 1024, file_desc)) != 0)
	    MD5_Update (&md_context, data, bytes);
	MD5_Final (c,&md_context);
	strcpy(sum, c);
	sum[LEN_MD5] = '\0';
	fclose (file_desc);
}

// Checks the md5 hash of the file
// with the given md5
int check_md5(char *file_name, char *sum) {
	char c[MD5_DIGEST_LENGTH + 1];
    calculate_md5(file_name,c);
    c[LEN_MD5] = '\0';
	return strcmp(sum,c);
}

// Updates the file structure of 
// the shared directory
void update_file_structures(char *server_share_dir) {
	int i,j;
	DIR *directory;
	struct dirent *ep;
	directory = opendir(server_share_dir);
	if(directory == NULL) {
		perr("[SERVER] Opening Share Directory Failed.\n");
	}
	i = 0;
	while(ep = readdir(directory)) {
		strcpy(server_fs[i].file_name, ep->d_name);
		server_fs[i].file_name[strlen(server_fs[i].file_name)] = '\0';
		struct stat info;
		stat(ep->d_name, &info);
		server_fs[i].file_size = info.st_size;
		switch (info.st_mode & S_IFMT) {
			case S_IFBLK:  strcpy(server_fs[i].file_type,"Block Device\0");break;
			case S_IFCHR:  strcpy(server_fs[i].file_type,"Charecter Device\0");break;
			case S_IFDIR:  strcpy(server_fs[i].file_type,"Directory\0");break;
			case S_IFIFO:  strcpy(server_fs[i].file_type,"Pipe\0");break;
			case S_IFLNK:  strcpy(server_fs[i].file_type,"Symbolic Link\0");break;
			case S_IFREG:  strcpy(server_fs[i].file_type,"Regular File\0");break;
			case S_IFSOCK: strcpy(server_fs[i].file_type,"Socket\0");break;
			default:       strcpy(server_fs[i].file_type,"Unknown Type\0");break;
		}
		sprintf(server_fs[i].file_time, "%s" ,ctime(&(info.st_mtime)));
		server_fs[i].file_time[strlen(server_fs[i].file_time) - 1] = '\0'; // find a better way then. :/
		if( (info.st_mode & S_IFMT) == S_IFREG) {
			calculate_md5(server_fs[i].file_name, server_fs[i].file_md5);
		}
		else {
			for(j = 0; j < MD5_DIGEST_LENGTH; j++) {
				server_fs[i].file_md5[j] = 'a';
			}
		}
		server_fs[i].file_md5[LEN_MD5] = '\0';
		i++;
	}
	server_file_count = i;
	closedir(directory); 
}

// Converts filesize
// to human readable form
char* readable_fs(double size, char *buf) {
    int i = 0;
    const char* units[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }
    sprintf(buf, "%.*f %s", i, size, units[i]);
    return buf;
}

// Resets the server variables
// after each response.
void client_mem_reset() {
	int i;
	for(i=0;i<MAX_QUERY_SIZE;i++) {
		client_arg_string[i] = '\0';
		input_arg_string[i] = '\0';
	}
	for(i=0;i<MAX_ARGS;i++) {
		arguments[i] = NULL;
	}
	arg_size = 0;
}

// Resets the server variables
// after each request.
void server_mem_reset() {
	int i;
	for(i=0;i<MAX_QUERY_SIZE;i++) {
		server_arg_string[i] = '\0';
		server_query_arg_string[i] = '\0';
	}
	for(i=0;i<MAX_ARGS;i++) {
		server_args[i] = NULL;
	}
	server_arg_size = 0;
}


// Client Side function to scan and parse the arguments.
// makes an array of pointers pointing to different arguments.
void scan_and_parse_arguments() {
	pout("\n>>");
	char c;
	int i = 0;
	arg_size = 0;
	for(i=0;(c = getchar()) != '\n';i++) {
		input_arg_string[i] = c;
		client_arg_string[i] = input_arg_string[i];
		if(c == ' ' || c == '\t' || i == 0) {
			arguments[arg_size] = input_arg_string + i;
			if(i != 0) {
				input_arg_string[i] = '\0';
				arguments[arg_size] += 1;
			}
			arg_size++;
		}
	}
	client_arg_string[i] = input_arg_string[i] = '\0';
}

// Server Side function to parse the request recieved.
// Makes an array of pointers pointing to different arguments.
void parse_request() {
	int i;
	char c;
	sprintf(server_arg_string,"%s",server_recv_data);
	sprintf(server_query_arg_string, "%s", server_recv_data);
	server_arg_size = 0;
	int len = strlen(server_arg_string);
	for(i=0;i<len;i++) {
		if(server_arg_string[i] == ' ' || server_arg_string[i] == '\t' || i == 0) { 
			server_args[server_arg_size] = server_arg_string + i;
			if(i != 0) {
				server_arg_string[i] = '\0';
				server_args[server_arg_size] += 1;
			}
			server_arg_size++;
		}
	}
	server_arg_string[i] = '\0';
}

//
// TODO: Remove Bug.
int get_time_difference(char *time1, char *time2) {
	struct tm tm;
	time_t t1,t2;
	if (strptime(time1, "%a-%b-%d-%T-%Y", &tm) == 0) {
		perr("[CLIENT] IndexGet Error.Time format is \'\%a-\%b-\%d-\%T-\%Y\'.\n");
	}
	t1 = mktime(&tm);
	if(t1 == -1) {
		perr("[CLIENT] IndexGet Error.\n");
	}
	if (strptime(time2, "%a-%b-%d-%T-%Y", &tm) == 0) {
		perr("[CLIENT] IndexGet Error.Time format is \'\%a-\%b-\%d-\%T-\%Y\'.\n");
	}
	t2 = mktime(&tm);
	if(t2 == -1) {
		perr("[CLIENT] IndexGet Error.\n");
	}
	return difftime(t1,t2);
}

//
//
void clientside_index_get_functionality(int file_count) {
	int i;
	if( arguments[1] == NULL || strcmp(arguments[1],"--longlist") == 0) {
		pout("\n---- Shared Directory Index ------\n\n");
		for(i=0;i<file_count; i++) {
			char buf[10];
			printf("%s\t\t%s\t\t%s\n",client_fs[i].file_name,readable_fs(client_fs[i].file_size, buf),client_fs[i].file_type);
		}
		pout("\n\n-------------- End ---------------\n");
	}
	else if(strcmp(arguments[1],"--shortlist") == 0) {
		if(arg_size < 4) {
			perr("[CLIENT] Not Enough Arguments.\n");
			return;
		}
		pout("\n------------- Shortlist-----------\n\n");
		for(i=0;i<file_count; i++) {
			char buf[10];
			if(get_time_difference(arguments[2],client_fs[i].file_time) >=0 && get_time_difference(client_fs[i].file_time,arguments[3]) >=0)
				printf("%s\t\t%s\t\t%s\n",client_fs[i].file_name,readable_fs(client_fs[i].file_size, buf),client_fs[i].file_type);
		}
		pout("\n\n-------------- End ---------------\n");	
	}
	else if(strcmp(arguments[1],"--regex") == 0) {
		if(arg_size < 3) {
			perr("[CLIENT] Not Enough Arguments.\n");
			return;
		}
		regex_t regex;
		int rv = regcomp(&regex, arguments[2], 0);
		if (rv != 0) {
			perr("[CLIENT] Could not compile regex\n");
			return;
		}
		pout("\n---- Files ------\n\n");
		for(i=0;i<file_count; i++) {
			if(regexec(&regex, client_fs[i].file_name, 0, NULL, 0) == 0) {
				char buf[10];
				printf("%s\t\t%s\t\t%s\n",client_fs[i].file_name,readable_fs(client_fs[i].file_size, buf),client_fs[i].file_type);
			}
		}
		pout("\n\n------ End ------\n");
		regfree(&regex);
	}
}

//
//
void clientside_file_hash_functionality(int file_count) {
	int i,j;
	if( !arguments[1] || !strcmp(arguments[1],"--checkall") ) {
		pout("\n---- Shared Hash Index ------\n\n");
		for(i=0;i<file_count; i++) {
			char buf[10];
			printf("%s\t\t%s\t\t",client_fs[i].file_name,client_fs[i].file_time);
			for(j = 0; j< MD5_DIGEST_LENGTH; j++) {
				printf("%02x",client_fs[i].file_md5[j]);
			}
			printf("\n");
		}
		pout("\n\n-------------- End ---------------\n");
	}
	else if(!strcmp(arguments[1],"--verify")) {
		if(arg_size < 3) {
			perr("File Name not given");
			return;
		}
		pout("\n---- File Hash ----\n\n");
		for(i=0;i<file_count; i++) {
			if( strcmp(arguments[2],client_fs[i].file_name) == 0 ) {
				char buf[10];
				printf("%s\t\t%s\t\t",client_fs[i].file_name,client_fs[i].file_time);
				for(j = 0; j< MD5_DIGEST_LENGTH; j++) {
					printf("%02x",client_fs[i].file_md5[j]);
				}
				printf("\n");
			}
		}
		pout("\n---- End ----\n\n");
	}
	else {
		perr("Invalid Arguments to FileHash\n");
	}
}

//
//
void clientside_file_download_functionality(int sock, struct sockaddr_in server_addr, char *connection_type) {
	FILE *fp;	
	int i,recv_data_int;
	int bytes_recv;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	if(arg_size < 2) {
		perr("[CLIENT] Insufficient Arguments Provided to FileDownload.\n");
		return;
	}
	if(strcmp(connection_type, "tcp") == 0) {
		send(sock, client_arg_string, strlen(client_arg_string), 0);
		bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
	}
	else {
		sendto(sock, input_arg_string, strlen(input_arg_string), 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
	}
	recv_data[bytes_recv] = '\0';
	// The recieved data is either the file name or indication that no such file exists.
	if(strcmp(recv_data, "NoSuchFileExists&&&****@@@") == 0) {
		perr("[SERVER] No Such File Exists.\n");
		return;
	}
	else if(strcmp(recv_data, "FileExists!!!!###") == 0) {
		// We recieve the md5 and the packet_size
		if(strcmp(connection_type, "tcp") == 0) {
			recv_wrapper(sock, recv_data, 1024, 0);
		}
		else {
			recvfrom(sock, recv_data, 1024, 0, (struct sockaddr *)&server_addr, temp_sock_len);
		}
		strcpy(recv_md5,recv_data);
		recv_md5[LEN_MD5] = '\0';
		// Opening the file to write.
		fp = fopen(arguments[1], "w");
		if(fp == NULL) {
			perr("[CLIENT] File Can't be Opened for writing. Check Permissions.\n");
			return;
		}
		// First Packet 
		if(strcmp(connection_type, "tcp") == 0) {
			recv_wrapper(sock, &recv_data_int, sizeof(int), 0);
			bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
		}
		else {
			recvfrom(sock, &recv_data_int, sizeof(int), 0, (struct sockaddr *)&server_addr, temp_sock_len);
			bytes_recv = recvfrom( sock, recv_data, 1024, 0, (struct sockaddr *)&server_addr, temp_sock_len );
		}
		recv_data[bytes_recv] = '\0';
		while(strcmp(recv_data,"EndOfFile&&&****@@@") != 0) {
			for (i=0; i<recv_data_int; i++) {
				fprintf(fp,"%c",recv_data[i]);
			}
			if(strcmp(connection_type, "tcp") == 0) {
				recv_wrapper(sock, &recv_data_int, sizeof(int), 0);
				bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
			}
			else {
				recvfrom(sock, &recv_data_int, sizeof(int), 0, (struct sockaddr *)&server_addr, temp_sock_len);
				bytes_recv = recvfrom( sock, recv_data, 1024, 0, (struct sockaddr *)&server_addr, temp_sock_len );
			}
			recv_data[bytes_recv] = '\0';
		}
		// File Closed.
		// Being an idiot is hepful sometimes. You learn a lot. :)
		fclose(fp);
		// Close file downloaded.
		if(check_md5(arguments[1], recv_md5) == 0) {
			pout("[CLIENT] File Successfully Downloaded.\n");
		}
		else {
			perr("[CLIENT] Error While Downloading. Md5 Don't Match.\n");
		}
	}
	else {
		perr("[CLIENT] Wierd Shit Happened.\n");
	}
}

//
//
void clientside_file_upload_functionality(int sock, struct sockaddr_in server_addr, char *connection_type) {
	FILE *fp;	
	char c, send_md5[LEN_MD5 + 1];
	int i,recv_data_int,count;
	int bytes_recv,junk = 0;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	if(arg_size < 2) {
		perr("[CLIENT] Insufficient Arguments Provided to FileUpload.\n");
		return;
	}
	fp = fopen(arguments[1],"r");
	if(fp == NULL) {
		perr("[CLIENT] No such File exists to upload.\n");
		return;
	}
	fclose(fp);
	// Arguments and Request Acceptance.
	if(strcmp(connection_type, "tcp") == 0) {
		send(sock, client_arg_string, strlen(client_arg_string), 0);
		bytes_recv = recv_wrapper(sock, recv_data, 1024, 0); 
	}
	else {
		sendto(sock, client_arg_string, strlen(client_arg_string), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
	}
	recv_data[bytes_recv] = '\0';
	if(strcmp(recv_data,"FileDenyRequest") == 0) {
		perr("[CLIENT] Upload Request Denied.\n");
		return;	
	}
	else if(strcmp(recv_data,"FileAllowRequest") == 0) {
		pout("[CLIENT] Upload Request Accepted.\n");
		calculate_md5(arguments[1], send_md5);
		if(strcmp(connection_type, "tcp") == 0) {
			send(sock, send_md5, strlen(send_md5), 0);
		}
		else {
			sendto(sock, send_md5, strlen(send_md5), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		}
		fp = fopen(arguments[1], "r");
		while(fscanf(fp, "%c",&c)!=EOF) {
			count = 0;
			send_data[count++] = c;
			while(count < 1024 && fscanf(fp, "%c",&c) != EOF) {
				send_data[count++] = c;
			}
			server_send_data[count] = '\0';
			if (strcmp(connection_type, "tcp") == 0) {
				send(sock, &count, sizeof(int), 0); // packet_size.
				send(sock, send_data, 1024,0); // packet_contents.
			}
			else {
				sendto(sock, &count, sizeof(int), 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
				sendto(sock, send_data, 1024, 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
			}
		}
		if (strcmp(connection_type, "tcp") == 0) {
			send(sock, &junk, sizeof(int), 0);
			send(sock, "EndOfFile&&&****@@@\0", 1024, 0);
		}
		else {
			sendto(sock, &junk,  sizeof(int), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
			sendto (sock, "EndOfFile&&&****@@@\0", 1024, 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		}
		fclose(fp);
		pout("[CLIENT] Upload Complete.\n");
	}
	else {
		perr("[CLIENT] Unreachable state reached.\n");
	}
}

//
//
int exec_query_client(int sock, struct sockaddr_in server_addr, char *connection_type) {
	char send_data[1024], recv_data[1024];
	char recv_md5[LEN_MD5 + 1], calctd_md5[LEN_MD5 + 1];	
	int i,recv_data_int;
	int bytes_recv;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	if(strcmp(arguments[0],"Ping") == 0) {
		if(strcmp(connection_type, "tcp") == 0) {
			send(sock, client_arg_string, strlen(client_arg_string), 0);
			bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
		}
		recv_data[bytes_recv] = '\0';
		printf("%s",recv_data);
	}
	else if(strcmp(arguments[0],"IndexGet") == 0 || strcmp(arguments[0],"FileHash") == 0) {
		if(strcmp(connection_type, "tcp") == 0) {
			send(sock, client_arg_string, strlen(client_arg_string), 0);
			recv_wrapper(sock, &recv_data_int, sizeof(recv_data_int), 0);
		}
		else {
			sendto(sock, client_arg_string, strlen(client_arg_string), 0,(struct sockaddr *)&server_addr, sizeof(struct sockaddr));
			recvfrom(sock, &recv_data_int, sizeof(recv_data_int), 0,(struct sockaddr *)&server_addr, temp_sock_len);
		}
		int file_count = recv_data_int;
		for(i=0; i<file_count; i++){
			if(strcmp(connection_type, "tcp") == 0) {
				bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_name,recv_data);
				bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_time,recv_data);
				recv_wrapper(sock, &recv_data_int, sizeof(recv_data_int), 0);
				client_fs[i].file_size = recv_data_int;
				bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_type,recv_data);
				bytes_recv = recv_wrapper(sock, recv_data, 1024, 0);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_md5,recv_data);
			}
			else {
				bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_name,recv_data);
				bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_time,recv_data);
				recvfrom(sock, &recv_data_int, sizeof(recv_data_int), 0,(struct sockaddr *)&server_addr, temp_sock_len);
				client_fs[i].file_size = recv_data_int;
				bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_type,recv_data);
				bytes_recv = recvfrom(sock, recv_data, 1024, 0,(struct sockaddr *)&server_addr, temp_sock_len);
				recv_data[bytes_recv] = '\0';
				strcpy(client_fs[i].file_md5,recv_data);
			}
		}
		if(strcmp(arguments[0],"IndexGet") == 0) {
			clientside_index_get_functionality(file_count);
		}
		else if(strcmp(arguments[0],"FileHash") == 0){
			clientside_file_hash_functionality(file_count);
		}
	}
	else if(strcmp(arguments[0],"FileDownload") == 0) {
		clientside_file_download_functionality(sock, server_addr, connection_type);
	}
	else if(strcmp(arguments[0],"FileUpload") == 0) {
		clientside_file_upload_functionality(sock, server_addr, connection_type);
	}
	else if(strcmp(arguments[0],"Exit") != 0) {
		pout("\tp2p commands (Case Sensitive):\n");
		pout("\tNomenclature: [] - argument, {} - optional | - or\n\n");
		pout("\tIndexGet --[​shortlist|longlist|regex] [{[start­time­stamp][end­time­stamp]}|{regex}] : Gets file list of the peer.\n");
		pout("\tFileHash --[verify|checkall] {filename} : checks whether one/all files are changed or not.\n");
		pout("\tFileDownload [FilePath] : Download file on peer's list\n");
		pout("\tFileUpload [FilePath] : Upload file on peer's list given that peer sends in an approval signal\n");
		pout("\tExit");
	}
	else {
		perr("[CLIENT] Unreachable Condition. Contact Dev.\n");
	}
}

//
//
void serverside_index_hash_func(int sock, int connection, struct sockaddr_in client_addr, char* server_share_dir,char *connection_type) {
	int bytes_recv, i;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	update_file_structures(server_share_dir);
	if(strcmp(connection_type,"tcp") == 0) {
		send(connection, &server_file_count, sizeof(int), 0);
		for (i=0; i<server_file_count; i++) {
			send(connection, server_fs[i].file_name, 1024, 0);
			send(connection, server_fs[i].file_time, 1024, 0);
			send(connection, &server_fs[i].file_size, sizeof(server_fs[i].file_size), 0);
			send(connection, server_fs[i].file_type, 1024, 0);
			send(connection, server_fs[i].file_md5, 1024, 0);
		}
	}
	else {
		sendto(sock, &server_file_count, sizeof(int), 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		for (i=0; i<server_file_count; i++) {
			sendto(sock, server_fs[i].file_name, 1024, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			sendto(sock, server_fs[i].file_time, 1024, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			sendto(sock, &server_fs[i].file_size, sizeof(server_fs[i].file_size), 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			sendto(sock, server_fs[i].file_type, 1024, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			sendto(sock, server_fs[i].file_md5, 1024, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		}		
	}	
}

//
//
void serverside_file_download_func(int sock, int connection, struct sockaddr_in client_addr, char* server_share_dir,char *connection_type) {
	int bytes_recv;
	int junk = 0;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	char send_md5[1024];
	FILE *fp = fopen(server_args[1], "r");
	char c;
	int count;
	if(fp == NULL) {
		if (strcmp(connection_type, "tcp") == 0) {
			send (connection, "NoSuchFileExists&&&****@@@\0",1024,0);
		}
		else {
			sendto(sock, "NoSuchFileExists&&&****@@@\0",1024, 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		}
	}
	else {
		if (strcmp(connection_type, "tcp") == 0) {
			send (connection, "FileExists!!!!###\0",1024, 0);
		}
		else {
			sendto(sock, "FileExists!!!!###\0",1024, 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		}
		// Being an idiot is helpful sometimes. You learn a lot. :)
		fclose(fp);
		calculate_md5(server_args[1], send_md5);
		send_md5[LEN_MD5] = '\0';
		if (strcmp(connection_type, "tcp") == 0) {
			send (connection, send_md5, 1024,0);
		}
		else {
			sendto(sock, send_md5, 1024,0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		}
		fp = fopen(server_args[1], "r");
		while(fscanf(fp, "%c",&c)!=EOF) {
			count = 0;
			server_send_data[count++] = c;
			while(count < 1024 && fscanf(fp, "%c",&c) != EOF) {
				server_send_data[count++] = c;
			}
			server_send_data[count] = '\0';
			if (strcmp(connection_type, "tcp") == 0) {
				send(connection, &count, sizeof(int), 0); // packet_size.
				send(connection, server_send_data, 1024,0); // packet_contents.
			}
			else {
				sendto(sock, &count, sizeof(int), 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
				sendto(sock, server_send_data, 1024, 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			}
		}
		if (strcmp(connection_type, "tcp") == 0) {
			send(connection, &junk, sizeof(int), 0);
			send(connection, "EndOfFile&&&****@@@\0", 1024, 0);
		}
		else {
			sendto(sock, &junk,  sizeof(int), 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			sendto(sock, "EndOfFile&&&****@@@\0", 1024, 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
		}
		fclose(fp);
	}
}

//
//
void serverside_file_upload_func(int sock, int connection, struct sockaddr_in client_addr, char* server_share_dir,char *connection_type) {
	int i;
	int junk = 0;
	int sin_size = sizeof(struct sockaddr_in);
	socklen_t *temp_sock_len = (socklen_t *) &sin_size;
	if (strcmp(connection_type, "tcp") == 0) {
		send(connection, upload_string, 1024, 0);
	}
	else {
		sendto(sock, upload_string, 1024, 0,(struct sockaddr *)&client_addr, sizeof(struct sockaddr));
	}
	if(upload_flag == 0) {
		return;
	}
	char recv_md5[LEN_MD5 + 1];
	FILE *fp = fopen(server_args[1], "w");
	if(fp == NULL) {
		perr("[SERVER] File Can't be Opened.\n");
	}
	char c;
	int bytes_recv,count,server_recv_data_int;
	bytes_recv = recv_wrapper(connection,server_recv_data,1024,0);
	server_recv_data[bytes_recv] = '\0';
	strcpy(recv_md5, server_recv_data);
	recv_md5[LEN_MD5] = '\0';
	// First Packet 
	if(strcmp(connection_type, "tcp") == 0) {
		recv_wrapper(connection, &server_recv_data_int, sizeof(int), 0);
		bytes_recv = recv_wrapper(connection, server_recv_data, 1024, 0);
	}
	else {
		recvfrom(sock, &server_recv_data_int, sizeof(int), 0, (struct sockaddr *)&client_addr, temp_sock_len);
		bytes_recv = recvfrom(sock, server_recv_data, 1024, 0, (struct sockaddr *)&client_addr, temp_sock_len );
	}
	server_recv_data[bytes_recv] = '\0';
	while(strcmp(server_recv_data,"EndOfFile&&&****@@@") != 0) {
		for (i=0; i<server_recv_data_int; i++) {
			fprintf(fp,"%c",server_recv_data[i]);
		}
		if(strcmp(connection_type, "tcp") == 0) {
			recv_wrapper(connection, &server_recv_data_int, sizeof(int), 0);
			bytes_recv = recv_wrapper(connection, server_recv_data, 1024, 0);
		}
		else {
			recvfrom(sock, &server_recv_data_int, sizeof(int), 0, (struct sockaddr *)&client_addr, temp_sock_len);
			bytes_recv = recvfrom(sock, server_recv_data, 1024, 0, (struct sockaddr *)&client_addr, temp_sock_len );
		}
		server_recv_data[bytes_recv] = '\0';
	}
	// File Closed.
	// Being an idiot is hepful sometimes. You learn a lot. :)
	fclose(fp);
	// Close file downloaded.
	if(check_md5(server_args[1], recv_md5) == 0) {
		pout("[SERVER] File Successfully Downloaded.\n");
	}
	else {
		perr("[SERVER] Error While Downloading. Md5 Don't Match.\n");
	}
}

//
//
int exec_query_server(int sock, int connection, struct sockaddr_in server_addr, struct sockaddr_in client_addr, char *server_share_dir,char *connection_type) {
	if(strcmp(server_args[0],"Ping") == 0) {
		char str[6] = "Pong\n\0"; 
		send(connection, &str, strlen(str), 0);
	}
	// Send the whole file information here for IndexGet and FileHash. 
	// Let the client do what he wishes with that information.
	else if(strcmp(server_args[0], "IndexGet") == 0 || strcmp(server_args[0], "FileHash") == 0) { 
		serverside_index_hash_func(sock, connection, client_addr, server_share_dir, connection_type);
	}
	else if(strcmp(server_args[0],"FileDownload") == 0) {
		serverside_file_download_func(sock, connection, client_addr, server_share_dir, connection_type);
	}
	else if(strcmp(server_args[0],"FileUpload") == 0) {
		serverside_file_upload_func(sock, connection, client_addr, server_share_dir, connection_type);
	}
}

//
//
int peer_client_console(char *client_ip_addr, int client_port_number, char *connection_type) {
	int sock;
	struct hostent *host;
	struct sockaddr_in server_addr;
	host = gethostbyname(client_ip_addr);
	if(!host) {
		perr("[CLIENT] Invalid IP address.\n");
	}
	fprintf(stdout,"[CLIENT] Connected to host %s\n", client_ip_addr);
	if (strcmp(connection_type, "tcp") == 0) {
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1) {
			perr("[CLIENT] Unable to retrieve socket.\n");
			return 1;
		}
	}
	else if (strcmp(connection_type, "udp") == 0) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == -1) {
			perr("[CLIENT] Unable to retrieve socket.\n");
			return 1;
		}
	}
	pout("[CLIENT] Socket Retrieved.\n");
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(client_port_number);
	server_addr.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(server_addr.sin_zero),8);
	if (strcmp(connection_type, "tcp") == 0) {
		if (connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
			perr("[CLIENT] Unable to connect to port.\n");
			return 1;
		}
		printf(BOLDGREEN"[CLIENT] connected to port %d\n"RESET,client_port_number);
	}
	else if(strcmp(connection_type, "udp") == 0) {
		//TODO Bind UDP Socket
	}
	scan_and_parse_arguments();
	while(strcmp(arguments[0], "Exit") != 0) {
		exec_query_client(sock, server_addr, connection_type);
		client_mem_reset();
		scan_and_parse_arguments();
	}
	close(sock);
	return 0;
}

//
//
int peer_server(char *server_share_dir, int server_port_number, char *connection_type, int server_upload_flag) {
	upload_flag = server_upload_flag;
	if(upload_flag == 1) {
		strcpy(upload_string,"FileAllowRequest\0");
	}
	else {
		strcpy(upload_string,"FileDenyRequest\0");	
	}
	upload_string[strlen(upload_string)] = '\0';
	int sock, connection;
	struct sockaddr_in server_addr, client_addr;
	ssize_t bytes_recv;
	int sin_size;
	int server_recv_data_int;
	if(strcmp(connection_type, "tcp") == 0) {
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1){
			perr("[SERVER] Unable to retrieve socket.\n");
			return 1;
		}
	}
	else if(strcmp(connection_type, "udp") == 0) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == -1) {
			perr("[SERVER] Unable to retrieve socket.\n");
			return 1;
		}
	}
	pout("[SERVER] Socket Retrieved.\n");
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(server_port_number);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);
	// UDP.
	if(bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)  {
		perr("[SERVER] Unable to bind socket.\n");
		return 1;
	}
	pout("[SERVER] Socket Bound.\n");
	if (strcmp(connection_type, "tcp") == 0) {
		if (listen(sock, 10) == -1) {
			perr("[SERVER] Failed to listen.\n");
			return 1;
		}
	}
	pout("[SERVER] Listening To Socket.\n");
	while(1) {
		sin_size = sizeof(struct sockaddr_in);
		socklen_t *temp_sock_len = (socklen_t *) &sin_size;
		if (strcmp(connection_type, "tcp") == 0) {
			connection = accept(sock, (struct sockaddr *)&client_addr, temp_sock_len);
			fprintf(stdout,BOLDGREEN"[SERVER] Connection established with %s - %d"RESET"\n", 
					inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		}
		while(1) {
			if(strcmp(connection_type, "tcp") == 0) {
				bytes_recv = recv_wrapper(connection, server_recv_data, 1024, 0);
			}
			if(strcmp(connection_type, "udp") == 0) {
				bytes_recv = recvfrom(sock, server_recv_data, 1024, 0, (struct sockaddr *)&client_addr, temp_sock_len);
			}
			server_recv_data[bytes_recv] = '\0';
			fprintf(stdout,BOLDGREEN"[SERVER] Request Recieved - \"%s\""RESET "\n", server_recv_data);
			parse_request();
			//If the client closes a connection
			if( bytes_recv == 0 || strcmp(server_recv_data,"Exit") == 0) {
				pout("[SERVER] Connection Closed\n");
				close(connection);
				break;
			}
			exec_query_server(sock, connection, server_addr, client_addr, server_share_dir,connection_type);
		}
	}
	close(sock);
}

// Initial Help Information
// to start the program.
void init_help() {
	pout("p2p by Anurag Ghosh. Licensed under LGPL 3.0.\n");
	pout("Incorrect Arguments given to p2p.\n");
	pout("USAGE: p2p protocol --server share_dir upload_flag server_port --client listening_ip listening_port\n");
	pout("protocol : [tcp/udp]\n");
	pout("share_dir : directory path you want to share.\n");
	pout("upload_flag : Can be either 1 or 0 if you want to allow uploads or not.\n");
	pout("server_port : port that you want to host ypur server on.\n");
	pout("listening_ip : IP Address of peer you want to connect to.\n");
	pout("listening_port : port numbeer of peer you want to connect to.\n");
}

int main(int argc, char **argv) {
	if(argc != 9) {
		init_help();
		return 1;
	}
	int rv;
	pid_t pid;
	pid = fork();
	if(pid == -1) {
		perr("Fork Failed.\n");
		return 1;
	}
	else if(pid == 0) {
		rv = peer_server(argv[3],atoi(argv[5]), argv[1], atoi(argv[4]));
	}
	else {
		while(1) {
			int r = peer_client_console(argv[7], atoi(argv[8]), argv[1]);
			if(r <= 0) {
				break;
			}
			sleep(1);
		}
	}
	kill(pid, SIGQUIT);
	return 0;
}