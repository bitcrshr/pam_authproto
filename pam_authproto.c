/*
 * pam_authproto - PAM module for authentication (only)
 * See xsecurelock for the protocol between child process
 * 
 * Copyright (c) 2022  Niibe Yutaka <gniibe@fsij.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <poll.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <security/_pam_macros.h>

#define UNUSED __attribute__ ((unused))

/* If needed, please use gettext and po files to get translated message.  */
#define _(msgid) (msgid)

#define ENV_ITEM(n) { (n), #n }
static struct env_item {
  int item;
  const char *name;
} env_items[] = {
  ENV_ITEM(PAM_SERVICE),
  ENV_ITEM(PAM_USER),
  ENV_ITEM(PAM_TTY),
  ENV_ITEM(PAM_RHOST),
  ENV_ITEM(PAM_RUSER),
};

static int child_exited;

static void
sigchld_handler (int signum UNUSED)
{
  child_exited = 1;
}

static char buf[4096];

/* A packet is composed by two lines.
 *  - A line which specifies a kind of packet and length of message.
 *  - Another line of message.
 */
static int
read_packet (int fd, const char **r_msg)
{
  ssize_t len;
  int kind;
  unsigned long msg_len;
  char *p;

  buf[sizeof buf - 1] = 0;
  len = read (fd, buf, sizeof buf - 1);
  if (len < 0)
    {
      perror ("read error");
      return -1;
    }
  if (len == 0)
    return 0;

  if (buf[0] != 'i' && buf[0] != 'e' && buf[0] != 'U' && buf[0] != 'P')
    return -1;

  kind = buf[0];
  buf[0] = 0;

  if (len == 1)
    {
      *r_msg = buf;
      return kind;
    }

  if (buf[1] != ' ')
    return -1;
  else
    {
      msg_len = strtoul (&buf[2], &p, 10);
      if (p == &buf[2])
        return -1;
    }

  if (*p != '\n')
    return -1;

  p++;
  if (msg_len != (size_t)len - (size_t)(p - buf) - 1)
    return -1;

  p[msg_len - 1] = 0;
  *r_msg = p;
  return kind;
}

static int
write_packet (int fd, int kind, const char *msg)
{
  char line[256];
  const char *p;
  size_t r;
  ssize_t written;

  r = (size_t)snprintf (line, sizeof line, "%c %zd\n", kind, strlen (msg) - 1);
  if (r >= (int)sizeof line)
    return -1;

  p = line;
  while (r > 0)
    {
      written = write (fd, p, r);
      if (written < 0)
        return -1;
      p += written;
      r -= (size_t)written;
    }

  p = msg;
  r = strlen (msg);
  while (r > 0)
    {
      written = write (fd, p, r);
      if (written < 0)
        return -1;
      p += written;
      r -= (size_t)written;
    }

  return 0;
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  int debug = 0;
  int quiet = 0;
  int optargc;
  const char *logfile = NULL;
  pid_t pid;
  int io_fds[2];
  int r;

  if (argc < 1)
    {
      pam_syslog (pamh, LOG_ERR,
		  "This module needs at least one argument");
      return PAM_SERVICE_ERR;
    }

  for (optargc = 0; optargc < argc; optargc++)
    {
      const char *argN = argv[optargc];

      if (strcmp (argN, "debug") == 0)
	debug = 1;
      else if (strncmp (argN, "log=", 4) == 0)
	logfile = argN+4;
      else if (strcmp (argN, "quiet") == 0)
	quiet = 1;
      else
	break;
    }

  if (optargc >= argc)
    {
      pam_syslog (pamh, LOG_ERR, "No path given as argument");
      return PAM_SERVICE_ERR;
    }

  if (socketpair (AF_LOCAL, SOCK_SEQPACKET, 0, io_fds) != 0)
    {
      pam_syslog (pamh, LOG_ERR, "Could not create socketpair: %m");
      return PAM_SYSTEM_ERR;
    }

  pid = fork();
  if (pid == -1)
    return PAM_SYSTEM_ERR;

  if (pid > 0) /* parent */
    {
      sigset_t sigmask_orig;
      sigset_t sigmask_block;
      sigset_t sigmask_unblock;
      struct sigaction sa;
      sighandler_t sigpipe_handler;
      int waiting_output_from_child = 1;

      sigpipe_handler = signal (SIGPIPE, SIG_IGN);
      if (sigpipe_handler == SIG_ERR)
	{
	  pam_syslog (pamh, LOG_ERR, "signal error");
	  return PAM_SERVICE_ERR;
	}

      sigprocmask (SIG_SETMASK, NULL, &sigmask_block);
      sigprocmask (SIG_SETMASK, NULL, &sigmask_unblock);

      sigdelset (&sigmask_unblock, SIGCHLD);
      sigaddset (&sigmask_block, SIGCHLD);

      sa.sa_handler = sigchld_handler;
      sa.sa_flags = 0;
      sigemptyset (&sa.sa_mask);
      sigaction (SIGCHLD, &sa, NULL);

      /* Block SIGCHLD, to receive the signal synchronously.  */
      sigprocmask (SIG_SETMASK, &sigmask_block, &sigmask_orig);

      close (io_fds[1]);

      while (1)
	{
	  struct pollfd pollfd[1] = { { io_fds[0], POLLIN, 0 } };

	  child_exited = 0;
	  if (waiting_output_from_child)
	    {
	      r = ppoll (pollfd, 1, NULL, &sigmask_unblock);
	      if (r < 0 && errno != EINTR)
		{
		  pam_syslog (pamh, LOG_ERR, "ppoll returns with -1: %m");
		  r = PAM_SYSTEM_ERR;
		  break;
		}
	    }
	  else
	    sigsuspend (&sigmask_unblock);

	  if (child_exited)
	    {
	      int status = 0;

	      if (waitpid (pid, &status, 0) == (pid_t)-1)
		{
		  pam_syslog (pamh, LOG_ERR, "waitpid returns with -1: %m");
		  r = PAM_SYSTEM_ERR;
		}
	      else if (WIFEXITED (status))
		{
		  if (WEXITSTATUS (status) == 0)
		    r = PAM_SUCCESS;
		  else
		    r = PAM_AUTH_ERR;
		}
	      else if (WIFSIGNALED (status))
		{
		  pam_syslog (pamh, LOG_ERR, "%s failed: caught signal %d%s",
			      argv[optargc], WTERMSIG (status),
			      WCOREDUMP (status) ? " (core dumped)" : "");
		  if (!quiet)
		    pam_error (pamh, _("%s failed: caught signal %d%s"),
			       argv[optargc], WTERMSIG (status),
			       WCOREDUMP (status) ? " (core dumped)" : "");
		  r = PAM_SYSTEM_ERR;
		}
	      else
		{
		  pam_syslog (pamh, LOG_ERR, "%s failed: unknown status 0x%x",
			      argv[optargc], status);
		  if (!quiet)
		    pam_error (pamh, _("%s failed: unknown status 0x%x"),
			       argv[optargc], status);
		  r = PAM_SYSTEM_ERR;
		}
	      break;
	    }

	  if ((pollfd[0].revents & POLLIN))
	    {
	      size_t len;
              int conv_kind;
              const char *msg = NULL;

              conv_kind = read_packet (io_fds[0], &msg);
              if (conv_kind < 0)
		goto bad_interaction;
	      else if (conv_kind == 0)
		{
		  waiting_output_from_child = 0;
		  continue;
		}
	      else if (conv_kind == 'P')
		{
		  char *resp = NULL;

		  pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp, "%s", msg);
		  if (resp)
		    {
		      len = strlen (resp);
		      memcpy (buf, resp, len);
		      buf[len++] = '\n';
		      buf[len] = 0;
                      write_packet (io_fds[0], 'p', buf);
		      _pam_overwrite (resp);
		      _pam_drop (resp);
		    }
                  else
                    write_packet (io_fds[0], 'x', "\n");
		}
	      else if (conv_kind == 'U')
		{
		  char *resp = NULL;

                  pam_prompt (pamh, PAM_PROMPT_ECHO_ON, &resp, "%s", msg);
		  if (resp)
		    {
		      len = strlen (resp);
		      memcpy (buf, resp, len);
		      buf[len++] = '\n';
		      buf[len] = 0;
                      write_packet (io_fds[0], 'u', buf);
		      _pam_overwrite (resp);
		      _pam_drop (resp);
		    }
                  else
                    write_packet (io_fds[0], 'x', "\n");
		}
	      else if (conv_kind == 'e')
		pam_prompt (pamh, PAM_ERROR_MSG, NULL, "%s", msg);
	      else if (conv_kind == 'i')
		pam_prompt (pamh, PAM_TEXT_INFO, NULL, "%s", msg);
	      else
		{
		bad_interaction:
		  kill (pid, SIGTERM);
		  pam_syslog (pamh, LOG_ERR, "%s failed: bad interaction",
			      argv[optargc]);
		  r = PAM_SYSTEM_ERR;
		  break;
		}
	    }
	}

      /* Restore signal mask.  */
      sigprocmask (SIG_SETMASK, &sigmask_orig, NULL);
      /* Restore the signal handler.  */
      signal (SIGPIPE, sigpipe_handler);
      return r;
    }
  else /* child */
    {
      char **child_argv;
      int i;
      char **envlist, **tmp;
      int envlen, nitems;
      char *envstr;

      close (io_fds[0]);

      /* Set up stdin.  */
      if (dup2 (io_fds[1], STDIN_FILENO) == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup2 of STDIN failed: %m");
	  _exit (err);
	}

      /* Set up stdout.  */
      if (dup2 (io_fds[1], STDOUT_FILENO) == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "dup2 to STDOUT failed: %m");
	  _exit (err);
	}

      /* Set up stderr.  */
      if (logfile)
	{
	  time_t tm = time (NULL);
	  char *buffer = NULL;

	  if ((i = open (logfile, O_CREAT|O_APPEND|O_WRONLY,
			 S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1)
	    {
	      int err = errno;
	      pam_syslog (pamh, LOG_ERR, "open of %s failed: %m",
			  logfile);
	      _exit (err);
	    }
	  if (dup2 (i, STDERR_FILENO) == -1)
	    {
	      int err = errno;
	      pam_syslog (pamh, LOG_ERR, "dup2 failed: %m");
	      _exit (err);
	    }
	  close (i);

	  if (asprintf (&buffer, "*** %s", ctime (&tm)) > 0)
	    {
	      pam_modutil_write (STDERR_FILENO, buffer,
                                 (int)strlen (buffer));
	      free (buffer);
	    }
	}
      else
        {
	  if ((i = open ("/dev/null", O_WRONLY)) == -1)
	    {
	      int err = errno;
	      pam_syslog (pamh, LOG_ERR, "open of %s failed: %m",
			  "/dev/null");
	      _exit (err);
	    }
	  if (dup2 (i, STDERR_FILENO) == -1)
	    {
	      int err = errno;
	      pam_syslog (pamh, LOG_ERR, "dup2 failed: %m");
	      _exit (err);
	    }
	  close (i);
        }

      if (pam_modutil_sanitize_helper_fds (pamh, PAM_MODUTIL_IGNORE_FD,
					   PAM_MODUTIL_IGNORE_FD,
					   PAM_MODUTIL_IGNORE_FD) < 0)
	_exit(1);

      if (setsid () == -1)
	{
	  int err = errno;
	  pam_syslog (pamh, LOG_ERR, "setsid failed: %m");
	  _exit (err);
	}

      child_argv = calloc ((size_t)(argc - optargc + 1), sizeof (char *));
      if (child_argv == NULL)
	_exit (ENOMEM);

      for (i = 0; i < (argc - optargc); i++)
	child_argv[i] = strdup (argv[i+optargc]);
      child_argv[i] = NULL;

      envlist = pam_getenvlist (pamh);
      for (envlen = 0; envlist[envlen] != NULL; envlen++)
        ;
      nitems = sizeof (env_items) / sizeof (struct env_item);
      tmp = realloc (envlist,
                     (size_t)(envlen + nitems + 2) * sizeof (*envlist));
      if (tmp == NULL)
	{
	  free (envlist);
	  pam_syslog (pamh, LOG_CRIT, "realloc environment failed: %m");
	  _exit (ENOMEM);
	}
      envlist = tmp;
      for (i = 0; i < nitems; i++)
	{
	  const void *item;

	  if (pam_get_item (pamh, env_items[i].item, &item) != PAM_SUCCESS
	      || item == NULL)
	    continue;
	  if (asprintf (&envstr, "%s=%s", env_items[i].name, (const char *)item) < 0)
	    {
	      free (envlist);
	      pam_syslog (pamh, LOG_CRIT, "prepare environment failed: %m");
	      _exit (ENOMEM);
	    }
	  envlist[envlen++] = envstr;
	  envlist[envlen] = NULL;
	}

      if (asprintf (&envstr, "PAM_TYPE=%s", "auth") < 0)
        {
          free (envlist);
          pam_syslog (pamh, LOG_CRIT, "prepare environment failed: %m");
          _exit (ENOMEM);
        }
      envlist[envlen++] = envstr;
      envlist[envlen] = NULL;

      if (debug)
	pam_syslog (pamh, LOG_DEBUG, "Calling %s ...", child_argv[0]);

      execve (child_argv[0], child_argv, envlist);
      i = errno;
      pam_syslog (pamh, LOG_ERR, "execve(%s,...) failed: %m", child_argv[0]);
      free (envlist);
      _exit (i);
    }

  /* Never reached. */
  return PAM_SYSTEM_ERR;
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_chauthtok (pam_handle_t *pamh UNUSED, int flags UNUSED,
		  int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh UNUSED, int flags UNUSED,
		  int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_open_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}
