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
	char *path = get_word(dir);
	int ret_val = -1;

	if (path) {
		ret_val = chdir(path);
	} else {
		char *home = getenv("HOME");

		if (home) {
			ret_val = chdir(home);
		}
	}

	free(path);

	return ret_val;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */

	return SHELL_EXIT; /* Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */

	/* TODO: If builtin command, execute the command. */

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	} else if (pid == 0) {
		int ret_val = parse_command(cmd1, level + 1, cmd1->up);

		exit(ret_val);
	}

	parse_command(cmd2, level + 1, father);

	int status;

	waitpid(pid, &status, 0); /* wait for the command to finish*/
	if (WIFEXITED(status)) {
		return WEXITSTATUS(status);
	}

	return true;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */
	if (!c || level < 0)
		return SHELL_EXIT;

	if (c->op == OP_NONE) {
		/* Execute a simple command. */

		return parse_simple(c->scmd, level + 1, c); /* Replace with actual exit code of command. */
	}

	int ret_val = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		ret_val = parse_command(c->cmd1, level + 1, c);
		ret_val |= parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		ret_val = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		ret_val = parse_command(c->cmd1, level + 1, c);
		if (ret_val != 0)
			ret_val = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		ret_val = parse_command(c->cmd1, level + 1, c);
		if (ret_val == 0)
			ret_val = parse_command(c->cmd2, level + 1, c);

		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		ret_val = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

		break;

	default:
		return SHELL_EXIT;
	}

	return ret_val; /* Actual exit code of command. */
}
