#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_PATH_LEN 4096
#define MAX_TARGETS 10
#define MAX_COMMAND_LEN 1024
#define MAX_ARGS 20
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

volatile sig_atomic_t should_exit = 0;

typedef struct {
  char source_path[MAX_PATH_LEN];
  char target_paths[MAX_TARGETS][MAX_PATH_LEN];
  int target_count;
  pid_t monitor_pids[MAX_TARGETS];
  int active;
} backup_info_t;

backup_info_t active_backups[MAX_TARGETS];
int backup_count = 0;

void print_help(void);
void handle_signal(int sig);
void setup_signal_handlers(void);
int parse_command(char *command, char **args);
int create_directory_recursive(const char *path);
int copy_file(const char *src, const char *dest);
int copy_directory_recursive(const char *src, const char *dest);
int create_backup(const char *source, char targets[][MAX_PATH_LEN],
                  int target_count);
void monitor_directory(const char *source, const char *target);
int end_backup(const char *source, char targets[][MAX_PATH_LEN],
               int target_count);
void list_backups(void);
void cleanup_resources(void);
int path_exists(const char *path);
int is_directory(const char *path);
int is_dot_entry(const char *name);

int main(void) {
  char command[MAX_COMMAND_LEN];
  char *args[MAX_ARGS];
  int argc;

  printf("Interactive Backup Management System\n");
  printf("====================================\n\n");

  setup_signal_handlers();
  print_help();

  while (!should_exit) {
    printf("\nbackup> ");
    fflush(stdout);

    if (fgets(command, sizeof(command), stdin) == NULL) {
      if (feof(stdin)) {
        printf("\nEOF detected. Exiting...\n");
        break;
      }
      continue;
    }

    command[strcspn(command, "\n")] = 0;

    if (strlen(command) == 0) {
      continue;
    }

    argc = parse_command(command, args);
    if (argc == 0) {
      continue;
    }

    if (strcmp(args[0], "add") == 0) {
      if (argc < 3) {
        printf("Error: Usage: add <source_path> <target_path1> [target_path2] "
               "...\n");
      } else {
        char targets[MAX_TARGETS][MAX_PATH_LEN];
        int target_count = argc - 2;

        if (target_count > MAX_TARGETS) {
          printf("Error: Maximum %d target directories allowed\n", MAX_TARGETS);
        } else {
          for (int i = 0; i < target_count; i++) {
            strncpy(targets[i], args[i + 2], MAX_PATH_LEN - 1);
            targets[i][MAX_PATH_LEN - 1] = '\0';
          }

          if (create_backup(args[1], targets, target_count) == 0) {
            printf("Backup created successfully and monitoring started\n");
          }
        }
      }
    } else if (strcmp(args[0], "end") == 0) {
      if (argc < 3) {
        printf("Error: Usage: end <source_path> <target_path1> [target_path2] "
               "...\n");
      } else {
        char targets[MAX_TARGETS][MAX_PATH_LEN];
        int target_count = argc - 2;

        for (int i = 0; i < target_count; i++) {
          strncpy(targets[i], args[i + 2], MAX_PATH_LEN - 1);
          targets[i][MAX_PATH_LEN - 1] = '\0';
        }

        if (end_backup(args[1], targets, target_count) == 0) {
          printf("Backup monitoring stopped\n");
        }
      }
    } else if (strcmp(args[0], "list") == 0) {
      list_backups();
    } else if (strcmp(args[0], "restore") == 0) {
      printf("Command 'restore' not yet implemented\n");
    } else if (strcmp(args[0], "exit") == 0) {
      break;
    } else if (strcmp(args[0], "help") == 0) {
      print_help();
    } else {
      printf("Unknown command: %s\n", args[0]);
      printf("Type 'help' for available commands\n");
    }

    for (int i = 0; i < argc; i++) {
      free(args[i]);
    }
  }

  cleanup_resources();
  printf("Backup manager exited\n");
  return 0;
}

void print_help(void) {
  printf("Available commands:\n");
  printf("  add <source> <target1> [target2] ... - Create backup and start "
         "monitoring\n");
  printf("  end <source> <target1> [target2] ... - Stop backup monitoring\n");
  printf("  list - List active backups\n");
  printf("  restore <backup_path> <original_path> - Restore backup (not "
         "implemented)\n");
  printf("  exit - Exit the program\n");
  printf("  help - Show this help message\n");
}

void handle_signal(int sig) {
  switch (sig) {
  case SIGINT:
  case SIGTERM:
    should_exit = 1;
    break;
  }
}

void setup_signal_handlers(void) {
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
}

int parse_command(char *command, char **args) {
  int argc = 0;
  char *p = command;

  while (*p && argc < MAX_ARGS - 1) {
    while (*p && (*p == ' ' || *p == '\t')) {
      p++;
    }

    if (!*p)
      break;

    char *start = p;
    int len = 0;
    int in_quotes = 0;

    if (*p == '"') {
      in_quotes = 1;
      p++;
      start = p;

      while (*p && (*p != '"' || (p > start && *(p - 1) == '\\'))) {
        if (*p == '\\' && *(p + 1) == '"') {
          memmove(p, p + 1, strlen(p));
        }
        p++;
        len++;
      }

      if (*p == '"') {
        p++;
      }
    } else {
      while (*p && *p != ' ' && *p != '\t') {
        p++;
        len++;
      }
    }

    args[argc] = malloc(len + 1);
    if (args[argc] == NULL) {
      for (int i = 0; i < argc; i++) {
        free(args[i]);
      }
      return 0;
    }

    strncpy(args[argc], start, len);
    args[argc][len] = '\0';
    argc++;
  }

  return argc;
}

int create_directory_recursive(const char *path) {
  char tmp[MAX_PATH_LEN];
  char *p = NULL;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", path);
  len = strlen(tmp);

  if (len > 0 && tmp[len - 1] == '/') {
    tmp[len - 1] = 0;
  }

  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      if (mkdir(tmp, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        if (errno != EEXIST) {
          return -1;
        }
      }
      *p = '/';
    }
  }

  if (mkdir(tmp, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
    if (errno != EEXIST) {
      return -1;
    }
  }

  return 0;
}

int copy_file(const char *src, const char *dest) {
  int src_fd, dest_fd;
  char buffer[4096];
  ssize_t bytes_read, bytes_written;
  struct stat src_stat;

  if (lstat(src, &src_stat) != 0) {
    perror("lstat");
    return -1;
  }

  if (S_ISLNK(src_stat.st_mode)) {
    char link_target[MAX_PATH_LEN];
    ssize_t link_len = readlink(src, link_target, sizeof(link_target) - 1);
    if (link_len == -1) {
      perror("readlink");
      return -1;
    }
    link_target[link_len] = '\0';

    unlink(dest);
    if (symlink(link_target, dest) != 0) {
      perror("symlink");
      return -1;
    }
    return 0;
  }

  src_fd = open(src, O_RDONLY);
  if (src_fd < 0) {
    perror("open source");
    return -1;
  }

  dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, src_stat.st_mode);
  if (dest_fd < 0) {
    perror("open destination");
    close(src_fd);
    return -1;
  }

  while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
    bytes_written = write(dest_fd, buffer, bytes_read);
    if (bytes_written != bytes_read) {
      perror("write");
      close(src_fd);
      close(dest_fd);
      return -1;
    }
  }

  if (bytes_read < 0) {
    perror("read");
    close(src_fd);
    close(dest_fd);
    return -1;
  }

  close(src_fd);
  close(dest_fd);
  return 0;
}

int copy_directory_recursive(const char *src, const char *dest) {
  DIR *dir;
  struct dirent *entry;
  struct stat statbuf;
  char src_path[MAX_PATH_LEN];
  char dest_path[MAX_PATH_LEN];

  if (create_directory_recursive(dest) != 0) {
    printf("Error: Could not create directory %s: %s\n", dest, strerror(errno));
    return -1;
  }

  dir = opendir(src);
  if (dir == NULL) {
    printf("Error: Could not open directory %s: %s\n", src, strerror(errno));
    return -1;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (is_dot_entry(entry->d_name)) {
      continue;
    }

    snprintf(src_path, sizeof(src_path), "%s/%s", src, entry->d_name);
    snprintf(dest_path, sizeof(dest_path), "%s/%s", dest, entry->d_name);

    if (lstat(src_path, &statbuf) != 0) {
      printf("Warning: Could not stat %s: %s\n", src_path, strerror(errno));
      continue;
    }

    if (S_ISDIR(statbuf.st_mode)) {
      if (copy_directory_recursive(src_path, dest_path) != 0) {
        closedir(dir);
        return -1;
      }
    } else {
      if (copy_file(src_path, dest_path) != 0) {
        printf("Warning: Could not copy file %s\n", src_path);
      }
    }
  }

  closedir(dir);
  return 0;
}

int path_exists(const char *path) {
  struct stat statbuf;
  return stat(path, &statbuf) == 0;
}

int is_directory(const char *path) {
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) {
    return 0;
  }
  return S_ISDIR(statbuf.st_mode);
}

int is_dot_entry(const char *name) {
  return (strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

int create_backup(const char *source, char targets[][MAX_PATH_LEN],
                  int target_count) {
  if (!path_exists(source)) {
    printf("Error: Source path '%s' does not exist\n", source);
    return -1;
  }

  if (!is_directory(source)) {
    printf("Error: Source path '%s' is not a directory\n", source);
    return -1;
  }

  for (int i = 0; i < target_count; i++) {
    if (path_exists(targets[i])) {
      if (!is_directory(targets[i])) {
        printf("Error: Target path '%s' exists but is not a directory\n",
               targets[i]);
        return -1;
      }

      DIR *dir = opendir(targets[i]);
      if (dir == NULL) {
        printf("Error: Cannot access target directory '%s': %s\n", targets[i],
               strerror(errno));
        return -1;
      }

      struct dirent *entry;
      int is_empty = 1;
      while ((entry = readdir(dir)) != NULL) {
        if (!is_dot_entry(entry->d_name)) {
          is_empty = 0;
          break;
        }
      }
      closedir(dir);

      if (!is_empty) {
        printf("Error: Target directory '%s' is not empty\n", targets[i]);
        return -1;
      }
    }
  }

  if (backup_count >= MAX_TARGETS) {
    printf("Error: Maximum number of backups reached\n");
    return -1;
  }

  backup_info_t *backup = &active_backups[backup_count];
  strncpy(backup->source_path, source, MAX_PATH_LEN - 1);
  backup->source_path[MAX_PATH_LEN - 1] = '\0';
  backup->target_count = target_count;
  backup->active = 1;

  for (int i = 0; i < target_count; i++) {
    strncpy(backup->target_paths[i], targets[i], MAX_PATH_LEN - 1);
    backup->target_paths[i][MAX_PATH_LEN - 1] = '\0';
  }

  printf("Creating initial backup...\n");
  for (int i = 0; i < target_count; i++) {
    printf("Copying to %s...\n", targets[i]);
    if (copy_directory_recursive(source, targets[i]) != 0) {
      printf("Error: Failed to create backup in %s\n", targets[i]);
      return -1;
    }
  }

  if (target_count > 0) {
    pid_t pid = fork();
    if (pid == 0) {
      // Child process - monitor directory
      monitor_directory(source, targets[0]);
      exit(0);
    } else if (pid > 0) {
      backup->monitor_pids[0] = pid;
    } else {
      perror("fork");
      return -1;
    }
  }

  backup_count++;
  return 0;
}

void monitor_directory(const char *source, const char *target) {
  int inotify_fd;
  char buffer[EVENT_BUF_LEN];

  printf("Monitoring %s -> %s (PID: %d)\n", source, target, getpid());

  inotify_fd = inotify_init();
  if (inotify_fd < 0) {
    perror("inotify_init");
    return;
  }

  int wd =
      inotify_add_watch(inotify_fd, source, IN_CREATE | IN_DELETE | IN_MODIFY);
  if (wd < 0) {
    perror("inotify_add_watch");
    close(inotify_fd);
    return;
  }

  while (!should_exit) {
    ssize_t length = read(inotify_fd, buffer, EVENT_BUF_LEN);
    if (length < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("read");
      break;
    }

    int i = 0;
    while (i < length) {
      struct inotify_event *event = (struct inotify_event *)&buffer[i];

      if (event->len > 0) {
        char src_path[MAX_PATH_LEN];
        char dest_path[MAX_PATH_LEN];

        snprintf(src_path, sizeof(src_path), "%s/%s", source, event->name);
        snprintf(dest_path, sizeof(dest_path), "%s/%s", target, event->name);

        if (event->mask & IN_CREATE) {
          printf("File created: %s\n", src_path);
          if (event->mask & IN_ISDIR) {
            copy_directory_recursive(src_path, dest_path);
          } else {
            copy_file(src_path, dest_path);
          }
        } else if (event->mask & IN_DELETE) {
          printf("File deleted: %s\n", src_path);
          if (event->mask & IN_ISDIR) {
            printf("Warning: Directory deletion not fully handled yet\n");
          } else {
            unlink(dest_path);
          }
        } else if (event->mask & IN_MODIFY) {
          printf("File modified: %s\n", src_path);
          if (!(event->mask & IN_ISDIR)) {
            copy_file(src_path, dest_path);
          }
        }
      }

      i += EVENT_SIZE + event->len;
    }
  }

  inotify_rm_watch(inotify_fd, wd);
  close(inotify_fd);
}

int end_backup(const char *source, char targets[][MAX_PATH_LEN],
               int target_count) {
  for (int i = 0; i < backup_count; i++) {
    if (strcmp(active_backups[i].source_path, source) == 0) {
      int matches = 0;
      for (int j = 0; j < active_backups[i].target_count; j++) {
        for (int k = 0; k < target_count; k++) {
          if (strcmp(active_backups[i].target_paths[j], targets[k]) == 0) {
            matches++;
            break;
          }
        }
      }

      if (matches == target_count &&
          matches == active_backups[i].target_count) {
        if (kill(active_backups[i].monitor_pids[0], SIGTERM) != 0) {
          printf("Warning: Failed to terminate process: %s\n", strerror(errno));
        } else {
          waitpid(active_backups[i].monitor_pids[0], NULL, 0);
        }

        for (int j = i; j < backup_count - 1; j++) {
          active_backups[j] = active_backups[j + 1];
        }
        backup_count--;

        return 0;
      }
    }
  }

  printf("Error: No matching backup found\n");
  return -1;
}

void list_backups(void) {
  if (backup_count == 0) {
    printf("No active backups\n");
    return;
  }

  printf("Active backups:\n");
  for (int i = 0; i < backup_count; i++) {
    printf("Source: %s\n", active_backups[i].source_path);
    printf("Targets:\n");
    for (int j = 0; j < active_backups[i].target_count; j++) {
      printf("  - %s\n", active_backups[i].target_paths[j]);
    }
    printf("\n");
  }
}

void cleanup_resources(void) {
  for (int i = 0; i < backup_count; i++) {
    for (int j = 0; j < active_backups[i].target_count; j++) {
      if (active_backups[i].monitor_pids[j] > 0) {
        kill(active_backups[i].monitor_pids[j], SIGTERM);
        waitpid(active_backups[i].monitor_pids[j], NULL, 0);
      }
    }
  }
}
