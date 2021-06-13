/*
 * Legion: Command-line interface
 */

#include "legion.h"
#include <string.h>
#include "stdio.h"
#define YELLOW   "\x1B[33m"
#define RESET "\x1B[0m"
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>


char *get_input(FILE *in);
int parse_input(char* input);
void exec_command(int command);
void run_cli(FILE *in, FILE *out);
void print_help();
void register_daemon();
void quit_program();
void unregister_daemon();
void get_status();
void get_status_all();
void start_daemon();
void stop_daemon();
void logrotate();
int get_position();
void start_timeout(int sig);
void stopping_daemon_handler_sigchld(int sig);
void stopping_daemon_handler_sigint(int sig);
void process_stopped_handler(int sig);



typedef struct daemon_info{
	char* name;
	int process_id;
	char* status;
	char* command;
	char* optional_args[1000];
	int file_version;
} DAEMON_INFO;

DAEMON_INFO daemon_list[1000];

FILE *output;

char input_values[1000][1000];
char *input_word_list[1000];
int num_args;
int daemon_running;
pid_t stopped_processes[100];

volatile sig_atomic_t start_position = -1;

/*
	DAEMON_INFO d;
	DAEMON_INFO *dp = &d;
	dp->name = "test";
	dp->process_id = 123;
	dp->current_status = "active";
	daemons[0] = *dp;
*/
int man_stopped = 0;
volatile sig_atomic_t is_stopped = 0;
/*
void process_stopped_handler(int s){
	if(man_stopped) {
		is_stopped = 1;
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);
		//int x;
		//int length = sizeof(daemon_list) / sizeof(daemon_list[0]);
		stopped_processes[0] = pid;
		//for(x = 0; x < length; x++){
		//	if(&stopped_processes[x] == NULL) { stopped_processes[x] = pid; break;}
		//}
	}
	return;
} */


void check_running_processes(){
	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);

	for(int x = 0; x < length; x++){
		if(daemon_list[x].name == NULL) {break;}
		int z = kill(daemon_list[x].process_id, 0);
		if(z == -1 && daemon_list[x].process_id > 0){
			sf_crash(daemon_list[x].name, daemon_list[x].process_id, 6);
			daemon_list[x].process_id = 0;
		}
	}
	return;
}

int ctrlc = 0;
void stopHandle(){
	ctrlc = 1;
	return;
}
void run_cli(FILE *in, FILE *out) {
	output = out;
	char *input;
	int command;
	daemon_running = 0;
/*
	struct sigaction end_process;
	end_process.sa_handler = process_stopped_handler;
	end_process.sa_flags = SA_RESTART;
	sigemptyset(&end_process.sa_mask);
	sigaction(SIGCHLD, &end_process, NULL);
*/
	//Loops through given input and runs command based on it
	while(1){
		memset(input_values, 0, sizeof(input_values));
		//signal(SIGINT, stopHandle);

		/*
		man_stopped = 0;
		if(is_stopped){
			printf("stopped");
			strcpy(daemon_list[0].status, "kill");
			is_stopped = 0;
			printf("%d", stopped_processes[0]);
		} */

		void check_running_processes();
		//if(ctrlc)
		//	quit_program();

		fprintf(output, YELLOW "legion> " RESET );
		fflush(out);
		input = get_input(in);
		void check_running_processes();

		if(input == NULL) {
			fflush(out);
			fprintf(output, "Error reading command\n");
			sf_error("Unable to parse input.");
			quit_program();
			break;
		}

		//char *copy = malloc(sizeof(char) * strlen(input));
		//strcpy(copy, input);
		command = parse_input(input);

		/*//exit
		if(command == 1){

			free(copy);
			break;
		}*/
		//free(copy);
		fflush(out);

		exec_command(command);
		if(command==1){
			free(input);
			break;
		}
		free(input);
	}
    // TO BE IMPLEMENTED
    return;
}

//Grab user input
char *get_input(FILE *in){
	char* buffer = malloc(sizeof(char) * 1024);
	size_t bufsize = 1024;
	char *z =fgets(buffer, bufsize, in);
	buffer[strcspn(buffer, "\n")] = '\0';

	//If null, returns nulls
	if(z == NULL) {free(buffer); return z;}
	return buffer;
}


/**
* Parses the value from the input, and returns the right number
* corresponding with the command to run
*/
int parse_input(char* val){
	//ADDS INPUT VALUES INTO GLOBAL 2d ARRAY
	char letter = 'c';
	int z = 0;
	int y = 0;
	num_args = 0;
	int quote = 0; //if quotation mark appears

	if(*val == EOF){return 1;}

	for(int x = 0; x < strlen(val); x++){
		letter = val[x];
		if(letter == EOF){break;}

		if(quote == 0){
			if(letter != ' ' && letter != '\''){
				input_values[y][z] = letter;
				z++;
			}
			else if(letter == ' '){
				input_values[y][z] = '\0';
				z = 0;
				y++;
				num_args++;
				continue;
			}
			else if(letter == '\''){
				quote= 1;
				continue;
			}
		}
		else{
			if(letter == '\''){
				quote = 0;
				input_values[y][z] = '\0';
				y++;
				//num_args++;
				continue;
			}
			else{
				input_values[y][z] = letter;
				z++;
				continue;
			}
		}
	}

	//printf("\n%s\n", input_values[0]);
	//printf("\n%d\n", num_args);
/*
	//Convert value to single char
	char word[1000];
	memset(word, 0, sizeof(word));

	char a = '1';
	int x = 0;
	while(a != '\0'){
		a = input_values[x][0];
		if(a == '\0'){
			break;
		}
		x++;
		strncat(word, &a, 1);
	}

	//printf("\n%s\n", word);
	int num_args = strlen(*input_values);


	char *input_word_list[100];
	input_word_list[0] = word;

	printf("\n%s\n", input_word_list[0]);
	*/


	if(num_args == 0){
		if(!strcmp(input_values[0], "help\0")) return 0;
		else if(!strcmp(input_values[0], "quit\0")) return 1;
		else if(!strcmp(input_values[0], "status-all\0")) return 5;
	}

	//2 argument values
	else if(num_args == 1){
		if(!strcmp(input_values[0], "unregister\0")) return 3;
		else if(!strcmp(input_values[0], "status\0")) return 4;
		else if(!strcmp(input_values[0], "start\0")) return 6;
		else if(!strcmp(input_values[0], "stop\0")) return 7;
		else if(!strcmp(input_values[0], "logrotate\0")) return 8;
		else if(!strcmp(input_values[0], "help\0")) return 0;
		else if(!strcmp(input_values[0], "quit\0")) return 1;
		else if(!strcmp(input_values[0], "status-all\0")) return 5;
	}
	else if(num_args >= 2){
		if(!strcmp(input_values[0], "register\0")) return 2;
	}

	//invalid args. Returns 0 and prints help message

	char *opt_args = input_values[0];
	for(int z=1; z < num_args+1; z++){
		char *opt = input_values[z];
		strcat(opt_args," ");
		strcat(opt_args, opt);
	}

	fprintf(output, "Unable to read command: %s", opt_args);
	char *reason = "Invalid Arguments";
	sf_error(reason);
	printf("\n");
	return 9;
}


/*
* Runs the command associated with input
*/
void exec_command(int command){
	switch(command) {
		/*
		* HELP: Print help message
		*/
		case 0:
			print_help();
			break;

		/*
		* QUIT: Exits the program, after first ensuring that any active daemons have been terminated
		*/
		case 1:
			quit_program();
			break;

		/*
		* REGISTER: Registers the name of a daemon and a command to be executed when the daemon is started.
		* The first argument is the name of a daemon, which can be arbitrarily chosen by the user.
		* The second argument is the name of an executable to run when the daemon is started.
		* Any remaining arguments become part of the argument vector passed when the executable is run
		*/
		case 2:
			register_daemon();
			break;

		/*
		* UNREGISTER: Unregisters a daemon previously registered under the specified name.
		* If no such daemon has been registered, or if daemon has been registered, but it is not
		* in the inactive state, then it is an error
		*/
		case 3:
			unregister_daemon();
			break;

		/*
		* STATUS: Prints the current status of the daemon registered under the specified name,
		* in a tab-separated format as follows (recall that the TAB character
		* has ASCII code 0x9 and can be represented in a C string literal by '\t')
		*/
		case 4:
			get_status();
			break;

		/*
		* STATUS-ALL: Prints the current status of all registered daemons, one per line.
		*/
		case 5:
			get_status_all();
			break;

		/*
		* START: Start the daemon that has been registered under the specified name.
		* If the current status of the daemon is anything other than inactive, it is an error
		*/
		case 6:
			start_daemon();
			break;

		/*
		* STOP: Attempt to stop the specified daemon.
		* If the current status of the daemon is exited or crashed, then it is simply set to inactive.
		* Otherwise, if the current status of the daemon is anything other than active, it is an error
		*/
		case 7:
			stop_daemon();
			break;

		/*
		* LOGROTATE: "Rotate" the log files for the specified daemon
		*/
		case 8:
			logrotate();
			break;

		case 9:
			break;
	}

	return;
}

void print_help(){
	fprintf(output, "Available commands: \n");
	fprintf(output, "help (0 args) Print this help message\n");
	fprintf(output, "quit (0 args) Quit the program\n");
	fprintf(output, "register (2 or more args) Register a daemon\n");
	fprintf(output, "unregister (1 args) Unregister a daemon\n");
	fprintf(output, "status (1 args) Show the status of a daemon\n");
	fprintf(output, "status-all (0 args) Show the status of all daemons\n");
	fprintf(output, "start (1 args) Start a daemon\n");
	fprintf(output, "stop (1 args) Stop a daemon\n");
	fprintf(output, "logrotate (1 args) Rotate log files for a daemon\n");
	return;
}

void register_daemon(){
	//daemons *daemons_list = malloc(10 *  sizeof(daemons));
	//DAEMON_INFO *dp = malloc(10*sizeof(DAEMON_INFO));
	//DAEMON_INFO* dp = malloc(10 * sizeof(struct daemon_info));
	//sets up the new daemon and stores it
	//char *name = malloc(sizeof(char) * strlen(input_values[1]));
	//strcpy(name, input_values[1]);

	int position = get_position();
	if(position != -1){
		sf_error("Daemon name already exists. Choose a new name");
		return;
	}

	DAEMON_INFO d;
	DAEMON_INFO *dp = &d;
	//strcpy(dp->name, input_values[1]);

	//printf("%s", input_values[1]);
	char* name = malloc(sizeof(char *) +1);
    strcpy(name, input_values[1]);
	dp->name = name;

	dp->process_id = 0;

	char* command = malloc(sizeof(char *)+1);
    strcpy(command, input_values[2]);
	dp->command = command;

	char* status = malloc(2* sizeof(char *));
   	strcpy(status, "inactive");
	dp->status = status;

	dp->file_version = 0;
	//char* opt = malloc(sizeof(char *));
	dp->optional_args[0] = dp->command;

	int count = 1;
	//printf("\n%d",num_args);
	for(int z=3; z < num_args+1; z++){
		char *arg = malloc(sizeof(char *)+1);
		strcpy(arg, input_values[z]);
		dp->optional_args[count] = arg;
		count++;
	}
	dp->optional_args[count] = NULL;


	//Stores the daemon process in the next free spot in the struct
	int x;
	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);

	for(x = 0; x < length; x++){
		if(daemon_list[x].name == NULL) { daemon_list[x] = *dp; break;}
	}
	sf_register(input_values[1], input_values[2]);


	return;
}

void quit_program(){
	//Loops through every daemon process in the struct to make sure its exited
	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);
	for(int x = 0; x < length; x++){
		if(daemon_list[x].name == NULL) { break;}
		//If not exited, then must terminate the process
		if(!(strcmp(daemon_list[x].status, "active"))){
			strcpy(input_values[1], daemon_list[x].name);
			stop_daemon();
			//strcpy(daemon_list[x].status, "exited");
			//MUST EXIT
			//printf("Not EXITED\n");
		}
		free(daemon_list[x].name);
		free(daemon_list[x].command);

		int m = sizeof(daemon_list[x].optional_args) / sizeof(daemon_list[x].optional_args[0]);
		for(int y = 1; y < m; y++){
			char* l = daemon_list[x].optional_args[y];
			if(l == NULL) break;

			free(daemon_list[x].optional_args[y]);
		}
		//free(daemon_list[x].optional_args);
		free(daemon_list[x].status);
		//free(&daemon_list[x]);

	}

	return;
}

void unregister_daemon(){
	//Find position of the daemon in the list
	int position = get_position();

	//Print error message if it doesnt exist
	if(position == -1){
		fprintf(output, "Daemon %s is not registered\n", input_values[1]);

		sf_error("Invalid command");
		return;
	}

	if(strcmp(daemon_list[position].status, "inactive")){
		fprintf(output, "Daemon %s is not inactive\n", input_values[1]);

		sf_error("Invalid command");
		return;
	}
	//Free the memory values and remove from array
	free(daemon_list[position].name);
	free(daemon_list[position].command);
	//free(daemon_list[position].optional_args);
	free(daemon_list[position].status);

	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);
	for(int y = position; y < length-1; y++){
		daemon_list[y] = daemon_list[y+1];
		if(daemon_list[y].name == NULL){
			break;
		}
	}
	int x = position;
	int m = sizeof(daemon_list[x].optional_args) / sizeof(daemon_list[x].optional_args[0]);
	for(int y = 1; y < m; y++){
		char* l = daemon_list[x].optional_args[y];
		if(l == NULL) break;
		free(daemon_list[x].optional_args[y]);
	}
	sf_unregister(input_values[1]);

	return;
}

void get_status(){
	int position = get_position();
	if(position != -1)
		fprintf(output, "%s \t %d \t %s \n", daemon_list[position].name, daemon_list[position].process_id, daemon_list[position].status);
	else {
		fprintf(output, "%s \t %d \t %s \n", input_values[1], 0, "unknown");
	}
	return;
}

void get_status_all(){
	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);
	for(int x = 0; x < length; x++){
		if(daemon_list[x].name == NULL) { break;}
		fprintf(output, "%s \t %d \t %s \n", daemon_list[x].name, daemon_list[x].process_id, daemon_list[x].status);

	}
	return;
}

void start_daemon(){

	//gets position of daemon in list
	int position = get_position();
	start_position = get_position();

	if(position == -1){
		fprintf(output, "Daemon %s is not registered. Cannot start\n", input_values[1]);
		sf_error("Invalid command");
		return;
	}
	if(strcmp(daemon_list[position].status, "inactive")){
		fprintf(output, "Daemon status is %s when it should be \'inactive\'\n", daemon_list[position].status);
		sf_error("Invalid command");
		return;
	}

	//set states
	strcpy(daemon_list[position].status, "starting");
	sf_start(daemon_list[position].name);

	int fd[2];
	int x = pipe(fd);

	pid_t pid = fork();
	if (x == -1) {
        sf_error("PIPE ISSUE");
        return;
    }

	//error
	if(pid < 0){
		sf_error("Fork failed\n");
		strcpy(daemon_list[position].status, "inactive");
		sf_reset(daemon_list[position].name);
		return;
	}

	//Child
	if(pid == 0 ){

		//create and join a new process group
		setpgid(pid,0);

		//Redirects the output side of the pipe to file descriptor
		dup2(fd[1], SYNC_FD);

		//create log file and redirect output
		FILE *f = NULL;
		mkdir(LOGFILE_DIR, 0777);
		char f_name[1000];
		sprintf(f_name, "%s/%s.log.%c", LOGFILE_DIR, daemon_list[position].name, '0');
		f = freopen(f_name, "a+", stdout);

		//run command
		char path[100] = "";
    	strcat(path,DAEMONS_DIR);
    	strcat(path,":");
    	strcat(path, getenv("PATH"));
		setenv("PATH", path, 1);

		//char* word[1000] = {daemon_list[position].command, daemon_list[position].optional_args[0], NULL};
		daemon_running++;

		int x = execvpe(daemon_list[position].command, daemon_list[position].optional_args, environ);
		//free(path);
		if(x == -1){
			sf_error("Program could not be started");
			daemon_running--;
			strcpy(daemon_list[position].status, "crashed");
			fclose(f);
			close(fd[1]);
	 		exit(0);
		}
		else{
			sf_error("no error");
		}

    	//dup2(1, fileno(f));
		fclose(f);
		close(fd[1]);
		//daemon_running--;
	 	exit(0);
	}


	//parent
	if(pid > 0){

		daemon_list[position].process_id = pid;

		//Set alarm for timeout
		struct sigaction action;
		action.sa_handler = start_timeout;
		action.sa_flags = 0;
		sigemptyset(&action.sa_mask);
		sigaction(SIGALRM, &action, NULL);
		alarm(CHILD_TIMEOUT);

		char sync_msg[1];
		int n = read(fd[0], sync_msg, 1);

		sigset_t mask;
		sigemptyset(&mask);
		//
		sigaddset(&mask, SIGTERM);
		sigprocmask(SIG_BLOCK, &mask, NULL);

		//Successful read, set to active
		if(n != -1){
			alarm(0);
			man_stopped = 1;
			sigprocmask(SIG_UNBLOCK, &mask, NULL);
			strcpy(daemon_list[position].status, "active");
			sf_active(daemon_list[position].name, daemon_list[position].process_id);
			close(fd[0]);
			return;
		}
		else {
			if(start_position != -2) {
				alarm(0);
				sf_error("Couldnt read");
			}
		}

		//Kill processes if not able to be read
		if(start_position == -2){
			//int status;
			//waitpid(pid, &status, WNOHANG);
			man_stopped = 1;
			//sf functions
			sf_kill(daemon_list[position].name, daemon_list[position].process_id);
			sf_crash(daemon_list[position].name, 0, SIGKILL);
			sf_error("No sync message recieved");

			//Kill and set state
			kill(daemon_list[position].process_id, SIGKILL);
			daemon_list[position].process_id = 0;
			strcpy(daemon_list[position].status, "crashed");
			start_position = -1;
			return;
		}

		return;
	}

	return;
}

void start_timeout(int sig){
	start_position = -2;
	return;
}

volatile sig_atomic_t daemon_stopped_chld = 0;
volatile sig_atomic_t daemon_kill = 0;


void stop_daemon(){
	int position = get_position();
	if(position == -1){
		sf_error("Invalid input");
		return;
	}

	//status is exited or crashed then set to inactive
	if(!strcmp(daemon_list[position].status, "exited")) {
		strcpy(daemon_list[position].status, "inactive");
		sf_reset(daemon_list[position].name);
		return;
	}

	if(!strcmp(daemon_list[position].status, "crashed")) {
		strcpy(daemon_list[position].status, "inactive");
		sf_reset(daemon_list[position].name);
		return;
	}

	//Status is anything but active, return error
	if(strcmp(daemon_list[position].status, "active")) {
		sf_error("Daemon is not active");
		return;
	}

	//Stop the daemon
	strcpy(daemon_list[position].status, "stopping");
	kill(daemon_list[position].process_id, SIGTERM);
	sf_stop(daemon_list[position].name, daemon_list[position].process_id);

	//struct sigaction sigchld, sigint;
	//sigchld.sa_handler = stopping_daemon_handler_sigchld;
	//sigaction(SIGCHLD, &sigchld, NULL);
	//sigint.sa_handler = stopping_daemon_handler_sigint;
	//sigaction(SIGCHLD, &sigint, NULL);

	struct sigaction action;
	action.sa_handler = stopping_daemon_handler_sigint;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGALRM, &action, NULL);
	alarm(CHILD_TIMEOUT);

	//struct sigaction chld_action;
	//chld_action.sa_handler = stopping_daemon_handler_sigchld;
	//chld_action.sa_flags = 0;
	//sigemptyset(&chld_action.sa_mask);
	sigset_t mask, prev;
	signal(SIGCHLD, stopping_daemon_handler_sigchld);
	//sigaction(SIGCHLD, &chld_action, NULL);
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	while(1){
		sigprocmask(SIG_BLOCK, &mask, &prev);

		while(!daemon_stopped_chld){
			sigsuspend(&prev);

			if(daemon_kill == 1){
				alarm(0);
				sigprocmask(SIG_SETMASK, &prev, NULL);

				kill(daemon_list[position].process_id, SIGKILL);
				sf_kill(daemon_list[position].name, daemon_list[position].process_id);
				sf_crash(daemon_list[position].name, daemon_list[position].process_id, 9);
				sf_error("Unable to stop with SIGTERM. Sending SIGKILL");
				strcpy(daemon_list[position].status, "crashed");
				daemon_kill = 0;
				man_stopped = 1;
				return;
			}
		}

		alarm(0);
		daemon_kill = 0;

		sigprocmask(SIG_SETMASK, &prev, NULL);
		man_stopped = 1;
		sf_term(daemon_list[position].name, daemon_list[position].process_id, 0);
		strcpy(daemon_list[position].status, "exited");
			break;
	}

	daemon_stopped_chld = 0;
/*
	sigset_t mask, oldmask;
	sigemptyset(&mask);
	sigaddset (&mask, SIGCHLD);
	sigprocmask (SIG_BLOCK, &mask, &oldmask);
	sigsuspend(&mask);
	sigprocmask (SIG_UNBLOCK, &mask, NULL);
	//struct sigaction action;
	//action.sa_handler = stopping_daemon_handler;
	//sigaction(SIGCHLD, &action, NULL);
*/

	return;
}

void stopping_daemon_handler_sigchld(int sig){
	daemon_stopped_chld = waitpid(-1, NULL, 0);
	return;
}


void stopping_daemon_handler_sigint(int sig){
	daemon_kill = 1;

	return;
}

void logrotate(){
	int position = get_position();
	if(position == -1){
		sf_error("Daemon does not exist");
		return;
	}

	sf_logrotate(daemon_list[position].name);

	struct dirent *dir;
	DIR *directory = opendir(LOGFILE_DIR);
	char *del_fname = malloc(100);
	char *old_fname = malloc(100);
	char *new_fname = malloc(100);

	//Removes log file of max value and renames others
	while((dir = readdir(directory)) != NULL) {
		if(strstr(dir->d_name, daemon_list[position].name)){
			//Removes log file of max value
			char version = (dir->d_name[strlen(dir->d_name)-1])-48;
			if(version == LOG_VERSIONS) {
					strcpy(del_fname, LOGFILE_DIR);
					strcat(del_fname, "/");
					strcat(del_fname, dir->d_name);
					unlink(del_fname);
			}
			//Rename log files
			else if(version < LOG_VERSIONS && version >= 0){
				strcpy(old_fname, LOGFILE_DIR);
				strcat(old_fname, "/");
				strcat(old_fname, dir->d_name);

				strcpy(new_fname, LOGFILE_DIR);
				strcat(new_fname, "/");
				dir->d_name[strlen(dir->d_name)-1] = dir->d_name[strlen(dir->d_name)-1]+1;
				strcat(new_fname, dir->d_name);
				rename(old_fname, new_fname);
				//printf("%s\n", new_fname);
			}
		}

	}
	int stopped = 0;
	if(!strcmp(daemon_list[position].status, "active")){
		stop_daemon();
		stopped = 1;
		stop_daemon();
	}
	if(stopped == 1 ){
		start_daemon();
	}

	free(old_fname);
	free(new_fname);
	free(del_fname);
	free(directory);
	return;
}

int get_position(){
	if(daemon_list[0].name == NULL){ return -1;}

	int length = sizeof(daemon_list) / sizeof(daemon_list[0]);
	int position = -1;
	for(int x = 0; x < length; x++){
		if(daemon_list[x].name == NULL){ break;}

		if(!strcmp(daemon_list[x].name, input_values[1])) {
			position = x;
		 break;
		}
	}
	return position;
}