// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* Execute cd. */
	char *path = dir ? get_word(dir) : getenv("HOME");

	if (chdir(path) != 0) {
		if (dir)
			free(path);

		return false;
	}

	if (dir)
		free(path);

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */

	return SHELL_EXIT; /* Actual exit code. */
}

static void redirect_stdio_to_file(simple_command_t *s, char *verb, int stdio_type)
{
	// Determine file and flags based on stdioType
	char *file = get_word(stdio_type == 1 ? s->out : s->err);
	int flags = (s->io_flags & (stdio_type == 1 ? IO_OUT_APPEND : IO_ERR_APPEND))
				? O_WRONLY | O_APPEND | O_CREAT
				: O_WRONLY | O_TRUNC | O_CREAT;

	// Open file descriptor
	int fd = open(file, flags, 0644);

	if (fd == -1) {
		perror("Failed to open file for redirection");
		free(file);
		free(verb);
		exit(EXIT_FAILURE);
	}

	// Redirect either STDOUT or STDERR
	if (dup2(fd, stdio_type == 1 ? STDOUT_FILENO : STDERR_FILENO) == -1) {
		perror("Failed to duplicate file descriptor for redirection");
		close(fd);
		free(file);
		exit(EXIT_FAILURE);
	}

	close(fd);
	free(file);
}

static void redirect_both_stdio(simple_command_t *s, char *verb)
{
	char *filename = get_word(s->io_flags & IO_OUT_APPEND ? s->out : s->err);
	int file_open_mode = (s->io_flags & IO_OUT_APPEND) ? O_WRONLY | O_APPEND | O_CREAT : O_WRONLY | O_TRUNC | O_CREAT;
	int fd = open(filename, file_open_mode, 0644);

	if (fd < 0) {
		perror("failed to open file for redirection");
		free(filename);
		free(verb);
		exit(EXIT_FAILURE);
	}

	if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
		perror("failed to duplicate file descriptor");
		close(fd);
		free(filename);
		free(verb);
		exit(EXIT_FAILURE);
	}

	close(fd);
	free(filename);
}

static void create_or_truncate_file(word_t *redirect)
{
	if (redirect) {
		char *filename = get_word(redirect);
		int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0644);

		free(filename);
		close(fd);
	}
}

static int builtin_command(simple_command_t *s, char *command)
{
	if (strcmp(command, "cd") == 0) {
		free(command);

		/* check for each redirect possibility*/
		create_or_truncate_file(s->out);
		create_or_truncate_file(s->err);

		bool res = shell_cd(s->params);

		if (res == true)
			return 0;

		return -1;
	}

	/* Command was exit or quit */
	free(command);
	return shell_exit();
}

static int environment_assign(simple_command_t *s)
{
	const char *name = s->verb->string;
	char *env_val = get_word(s->verb->next_part->next_part);

	int res = setenv(name, env_val, 1);

	free(env_val);

	return res;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */

	if (s == NULL)
		return -1;

	/* If builtin command, execute the command. */
	char *verb = get_word(s->verb);

	if (strcmp(verb, "cd") == 0 || strcmp(verb, "exit") == 0 ||
		strcmp(verb, "quit") == 0) {
		return builtin_command(s, verb);
	}

	/*
	 * If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (strchr(verb, '=')) {
		free(verb);
		return environment_assign(s);
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t child_pid = fork();

	if (child_pid == -1) {
		perror("fork");
		free(verb);
		return child_pid;
	}

	if (child_pid > 0) {
		int status;

		waitpid(child_pid, &status, 0);
		free(verb);
		return WIFEXITED(status) ? WEXITSTATUS(status) : 0;
	}

	int argc = 0;
	char **argv = get_argv(s, &argc);

	// Handle input redirection if specified
	if (s->in) {
		char *input_file = get_word(s->in);
		int input_fd = open(input_file, O_RDONLY);

		if (input_fd < 0) {
			perror("Failed to open input file");
			free(input_file);
			free(verb);
			exit(EXIT_FAILURE);
		}

		if (dup2(input_fd, STDIN_FILENO) == -1) {
			perror("Failed to redirect standard input");
			close(input_fd);
			free(input_file);
			exit(EXIT_FAILURE);
		}

		close(input_fd);
		free(input_file);
	}

	/* redirect at both STDOUT and STDERR */
	if (s->out != NULL && s->err != NULL) {
		char *out = get_word(s->out);
		char *err = get_word(s->err);

		/* if same output file, open only once */
		if (!strcmp(out, err)) {
			redirect_both_stdio(s, verb);
		} else { /* else open each file separately */
			redirect_stdio_to_file(s, verb, 1);
			redirect_stdio_to_file(s, verb, 2);
		}

	} else { /* redirect only to STDOUT or STDERR */
		if (s->out)
			redirect_stdio_to_file(s, verb, 1);

		if (s->err)
			redirect_stdio_to_file(s, verb, 2);
	}

	/* launch new process */
	if (execvp(verb, argv) == -1) {
		fprintf(stderr, "Execution failed for '%s'\n", verb);

		free(verb);
		for (size_t i = 0; i < argc; ++i)
			free(argv[i]);

		free(argv);
		exit(EXIT_FAILURE);
	}

	free(verb);
	for (size_t i = 0; i < argc; ++i)
		free(argv[i]);

	free(argv);
	exit(EXIT_SUCCESS);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid_first_cmd = fork();

	if (pid_first_cmd < 0) {
		perror("error: can't create process; fork failed\n");
		return false;
	} else if (pid_first_cmd == 0) {
		/* Child process: exec first command */
		int exit_status = parse_command(cmd1, level + 1, cmd1->up);

		exit(exit_status);
	}

	int second_cmd_result = parse_command(cmd2, level + 1, father);
	int status;

	waitpid(pid_first_cmd, &status, 0); /* wait for the command to finish */

	if (WIFEXITED(status)) {
		int first_cmd_exit_status = WEXITSTATUS(status);

		return first_cmd_exit_status & second_cmd_result;
	}

	return second_cmd_result; /* Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */
	int pipe_fds[2];

	/* create a pipe*/
	if (pipe(pipe_fds) < 0) {
		perror("error: can't create pipe\n");
		return false;
	}

	/* create a process for the first command */
	pid_t pid_first_cmd = fork();

	if (pid_first_cmd < 0) {
		perror("error: can't create process; fork failed\n");
		return false;
	} else if (pid_first_cmd == 0) { /* if in child process */
		close(pipe_fds[0]);
		dup2(pipe_fds[1], STDOUT_FILENO);
		close(pipe_fds[1]);

		int exit_status = parse_command(cmd1, level + 1, cmd1->up);

		exit(exit_status);
	}

	pid_t pid_second_cmd = fork(); /* create another process for the second command */

	if (pid_second_cmd < 0) {
		perror("error: can't create process; fork failed\n");
		return false;
	} else if (pid_second_cmd == 0) {
		close(pipe_fds[1]);
		dup2(pipe_fds[0], STDIN_FILENO);
		close(pipe_fds[0]);

		int exit_status = parse_command(cmd2, level + 1, cmd2->up);

		exit(exit_status);
	}

	close(pipe_fds[0]);
	close(pipe_fds[1]);

	int status;

	waitpid(pid_second_cmd, &status, 0);

	return WIFEXITED(status) ? WEXITSTATUS(status) : false;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */

	if (c == NULL || level < 0)
		return SHELL_EXIT;

	/* Execute a simple command. */
	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level + 1, c); /* Actual exit code of command. */

	int res;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		res = parse_command(c->cmd1, level + 1, c);
		res |= parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		res = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		res = parse_command(c->cmd1, level + 1, c);

		if (res)
			res = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */

		res = parse_command(c->cmd1, level + 1, c);

		if (res == 0)
			res = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		res = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

		break;

	default:
		return SHELL_EXIT;
	}

	return res; /* Actual exit code of command. */
}

