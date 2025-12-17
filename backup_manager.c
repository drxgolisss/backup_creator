#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <time.h>

#define MAX_PATH_LEN 4096
#define MAX_TARGETS 10
#define MAX_COMMAND_LEN 1024
#define MAX_ARGS 20
#define MAX_WATCHES 1000
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

volatile sig_atomic_t should_exit = 0;

typedef struct {
    int wd;
    char path[MAX_PATH_LEN];
} watch_info_t;

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
int remove_directory_recursive(const char *path);
int create_backup(const char *source, char targets[][MAX_PATH_LEN], int target_count);
void monitor_directory(const char *source, const char *target);
int add_recursive_watches(int inotify_fd, const char *dir_path, watch_info_t *watches, int *watch_count);
int end_backup(const char *source, char targets[][MAX_PATH_LEN], int target_count);
void list_backups(void);
int restore_backup(const char *backup_path, const char *original_path);
void cleanup_resources(void);
int path_exists(const char *path);
int is_directory(const char *path);
int is_target_inside_source(const char *source, const char *target);
int files_are_same(const char *file1, const char *file2);
int sync_directories(const char *backup_dir, const char *original_dir);
int is_dot_entry(const char *name);
void safe_path_join(char *dest, size_t dest_size, const char *dir, const char *name);

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
                printf("Error: Usage: add <source_path> <target_path1> [target_path2] ...\n");
                continue;
            }
            
            char targets[MAX_TARGETS][MAX_PATH_LEN];
            int target_count = argc - 2;
            
            if (target_count > MAX_TARGETS) {
                printf("Error: Maximum %d target directories allowed\n", MAX_TARGETS);
                continue;
            }
            
            for (int i = 0; i < target_count; i++) {
                strncpy(targets[i], args[i + 2], MAX_PATH_LEN - 1);
                targets[i][MAX_PATH_LEN - 1] = '\0';
            }
            
            if (create_backup(args[1], targets, target_count) == 0) {
                printf("Backup created successfully and monitoring started\n");
            }
        }
        else if (strcmp(args[0], "end") == 0) {
            if (argc < 3) {
                printf("Error: Usage: end <source_path> <target_path1> [target_path2] ...\n");
                continue;
            }
            
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
        else if (strcmp(args[0], "list") == 0) {
            list_backups();
        }
        else if (strcmp(args[0], "restore") == 0) {
            if (argc != 3) {
                printf("Error: Usage: restore <backup_path> <original_path>\n");
                continue;
            }
            
            if (restore_backup(args[1], args[2]) == 0) {
                printf("Backup restored successfully\n");
            }
        }
        else if (strcmp(args[0], "exit") == 0) {
            break;
        }
        else if (strcmp(args[0], "help") == 0) {
            print_help();
        }
        else {
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
    printf("  add <source> <target1> [target2] ... - Create backup and start monitoring\n");
    printf("  end <source> <target1> [target2] ... - Stop backup monitoring\n");
    printf("  list - List active backups\n");
    printf("  restore <backup_path> <original_path> - Restore backup to original location\n");
    printf("  exit - Exit the program\n");
    printf("  help - Show this help message\n");
    printf("\nNote: Paths with spaces should be quoted, e.g., \"my directory\"\n");
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
        
        if (!*p) break;
        
        char *start = p;
        int len = 0;
        int in_quotes = 0;
        
        if (*p == '"') {
            in_quotes = 1;
            p++; 
            start = p;
            
            while (*p && (*p != '"' || (p > start && *(p-1) == '\\'))) {
                if (*p == '\\' && *(p+1) == '"') {
                    memmove(p, p + 1, strlen(p));
                }
                p++;
                len++;
            }
            
            if (*p == '"') {
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
    
    if (*p && argc >= MAX_ARGS - 1) {
        printf("Warning: Too many arguments, ignoring extras\n");
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
        
        safe_path_join(src_path, sizeof(src_path), src, entry->d_name);
        safe_path_join(dest_path, sizeof(dest_path), dest, entry->d_name);
        
        if (lstat(src_path, &statbuf) != 0) {
            printf("Warning: Could not stat %s: %s\n", src_path, strerror(errno));
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            if (copy_directory_recursive(src_path, dest_path) != 0) {
                printf("Error: Failed to copy subdirectory %s to %s\n", src_path, dest_path);
                closedir(dir);
                return -1;
            }
        } else {
            if (copy_file(src_path, dest_path) != 0) {
                printf("Warning: Could not copy file %s to %s: %s\n", 
                       src_path, dest_path, strerror(errno));
            }
        }
    }
    
    closedir(dir);
    return 0;
}

int remove_directory_recursive(const char *path) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char full_path[MAX_PATH_LEN];
    
    dir = opendir(path);
    if (dir == NULL) {
        if (unlink(path) != 0) {
            perror("unlink");
            return -1;
        }
        return 0;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (is_dot_entry(entry->d_name)) {
            continue;
        }
        
        safe_path_join(full_path, sizeof(full_path), path, entry->d_name);
        
        if (lstat(full_path, &statbuf) != 0) {
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            if (remove_directory_recursive(full_path) != 0) {
                closedir(dir);
                return -1;
            }
        } else {
            if (unlink(full_path) != 0) {
                perror("unlink");
                closedir(dir);
                return -1;
            }
        }
    }
    
    closedir(dir);
    
    if (rmdir(path) != 0) {
        perror("rmdir");
        return -1;
    }
    
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

void safe_path_join(char *dest, size_t dest_size, const char *dir, const char *name) {
    snprintf(dest, dest_size, "%s/%s", dir, name);
}

int is_target_inside_source(const char *source, const char *target) {
    char *real_source = realpath(source, NULL);
    if (real_source == NULL) {
        return 0; 
    }
    
    char target_copy[MAX_PATH_LEN];
    strncpy(target_copy, target, MAX_PATH_LEN - 1);
    target_copy[MAX_PATH_LEN - 1] = '\0';
    
    char *real_target = NULL;
    char *target_parent = NULL;
    
    real_target = realpath(target, NULL);
    
    if (real_target == NULL) {
        char *last_slash = strrchr(target_copy, '/');
        if (last_slash != NULL) {
            *last_slash = '\0';
            target_parent = realpath(target_copy, NULL);
            if (target_parent != NULL) {
                size_t parent_len = strlen(target_parent);
                size_t name_len = strlen(last_slash + 1);
                real_target = malloc(parent_len + name_len + 2);
                if (real_target != NULL) {
                    snprintf(real_target, parent_len + name_len + 2, "%s/%s", target_parent, last_slash + 1);
                }
                free(target_parent);
            }
        }
    }
    
    int result = 0;
    if (real_target != NULL) {
        size_t source_len = strlen(real_source);
        size_t target_len = strlen(real_target);
        
        if (target_len >= source_len) {
            if (strncmp(real_target, real_source, source_len) == 0) {
                if (target_len == source_len || real_target[source_len] == '/') {
                    result = 1;
                }
            }
        }
    }
    
    free(real_source);
    if (real_target) free(real_target);
    return result;
}

int create_backup(const char *source, char targets[][MAX_PATH_LEN], int target_count) {
    if (!path_exists(source)) {
        printf("Error: Source path '%s' does not exist\n", source);
        return -1;
    }
    
    if (!is_directory(source)) {
        printf("Error: Source path '%s' is not a directory\n", source);
        return -1;
    }
    
    for (int i = 0; i < target_count; i++) {
        if (is_target_inside_source(source, targets[i])) {
            printf("Error: Cannot create backup inside source directory\n");
            return -1;
        }
    }
    
    for (int i = 0; i < backup_count; i++) {
        if (strcmp(active_backups[i].source_path, source) == 0) {
            for (int j = 0; j < active_backups[i].target_count; j++) {
                for (int k = 0; k < target_count; k++) {
                    if (strcmp(active_backups[i].target_paths[j], targets[k]) == 0) {
                        printf("Error: Backup already exists for this source-target combination\n");
                        return -1;
                    }
                }
            }
        }
    }
    
    for (int i = 0; i < target_count; i++) {
        if (path_exists(targets[i])) {
            if (!is_directory(targets[i])) {
                printf("Error: Target path '%s' exists but is not a directory\n", targets[i]);
                return -1;
            }
            
            DIR *dir = opendir(targets[i]);
            if (dir == NULL) {
                printf("Error: Cannot access target directory '%s': %s\n", targets[i], strerror(errno));
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
    
    for (int i = 0; i < target_count; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            monitor_directory(source, targets[i]);
            exit(0);
        } else if (pid > 0) {
            backup->monitor_pids[i] = pid;
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
    watch_info_t watches[MAX_WATCHES];
    int watch_count = 0;
    char buffer[EVENT_BUF_LEN];
    
    printf("Monitoring %s -> %s (PID: %d)\n", source, target, getpid());
    
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return;
    }
    
    if (add_recursive_watches(inotify_fd, source, watches, &watch_count) != 0) {
        printf("Warning: Failed to set up some watches for %s\n", source);
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
                char *watch_path = NULL;
                for (int j = 0; j < watch_count; j++) {
                    if (watches[j].wd == event->wd) {
                        watch_path = watches[j].path;
                        break;
                    }
                }
                
                if (watch_path != NULL) {
                    char src_path[MAX_PATH_LEN];
                    char dest_path[MAX_PATH_LEN];
                    
                    snprintf(src_path, sizeof(src_path), "%s/%s", watch_path, event->name);
                    
                    const char *rel_path = src_path + strlen(source);
                    if (*rel_path == '/') rel_path++; 
                    
                    if (strlen(rel_path) > 0) {
                        snprintf(dest_path, sizeof(dest_path), "%s/%s", target, rel_path);
                    } else {
                        snprintf(dest_path, sizeof(dest_path), "%s/%s", target, event->name);
                    }
                    
                    if (event->mask & IN_CREATE) {
                        printf("File created: %s\n", src_path);
                        if (event->mask & IN_ISDIR) {
                            if (copy_directory_recursive(src_path, dest_path) != 0) {
                                printf("Warning: Failed to copy directory %s\n", src_path);
                            }
                            if (watch_count < MAX_WATCHES) {
                                int new_wd = inotify_add_watch(inotify_fd, src_path,
                                                              IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
                                if (new_wd >= 0) {
                                    watches[watch_count].wd = new_wd;
                                    strncpy(watches[watch_count].path, src_path, MAX_PATH_LEN - 1);
                                    watches[watch_count].path[MAX_PATH_LEN - 1] = '\0';
                                    watch_count++;
                                } else {
                                    printf("Warning: Failed to add watch for new directory %s: %s\n", 
                                           src_path, strerror(errno));
                                }
                            } else {
                                printf("Warning: Cannot add more watches (limit reached)\n");
                            }
                        } else {
                            if (copy_file(src_path, dest_path) != 0) {
                                printf("Warning: Failed to copy file %s\n", src_path);
                            }
                        }
                    }
                    else if (event->mask & IN_DELETE) {
                        printf("File deleted: %s\n", src_path);
                        if (event->mask & IN_ISDIR) {
                            if (remove_directory_recursive(dest_path) != 0) {
                                printf("Warning: Failed to remove directory %s\n", dest_path);
                            }
                        } else {
                            if (unlink(dest_path) != 0) {
                                printf("Warning: Failed to remove file %s: %s\n", 
                                       dest_path, strerror(errno));
                            }
                        }
                    }
                    else if (event->mask & IN_MODIFY) {
                        printf("File modified: %s\n", src_path);
                        if (!(event->mask & IN_ISDIR)) {
                            if (copy_file(src_path, dest_path) != 0) {
                                printf("Warning: Failed to update file %s\n", src_path);
                            }
                        }
                    }
                    else if (event->mask & IN_MOVED_FROM) {
                        printf("File moved from: %s\n", src_path);
                        if (event->mask & IN_ISDIR) {
                            if (remove_directory_recursive(dest_path) != 0) {
                                printf("Warning: Failed to remove moved directory %s\n", dest_path);
                            }
                        } else {
                            if (unlink(dest_path) != 0) {
                                printf("Warning: Failed to remove moved file %s: %s\n", 
                                       dest_path, strerror(errno));
                            }
                        }
                    }
                    else if (event->mask & IN_MOVED_TO) {
                        printf("File moved to: %s\n", src_path);
                        if (event->mask & IN_ISDIR) {
                            if (copy_directory_recursive(src_path, dest_path) != 0) {
                                printf("Warning: Failed to copy moved directory %s\n", src_path);
                            }
                        } else {
                            if (copy_file(src_path, dest_path) != 0) {
                                printf("Warning: Failed to copy moved file %s\n", src_path);
                            }
                        }
                    }
                }
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
    
    for (int i = 0; i < watch_count; i++) {
        inotify_rm_watch(inotify_fd, watches[i].wd);
    }
    close(inotify_fd);
}

int add_recursive_watches(int inotify_fd, const char *dir_path, watch_info_t *watches, int *watch_count) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char full_path[MAX_PATH_LEN];
    int errors = 0;
    
    int wd = inotify_add_watch(inotify_fd, dir_path,
                              IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd >= 0) {
        if (*watch_count < MAX_WATCHES) {
            watches[*watch_count].wd = wd;
            strncpy(watches[*watch_count].path, dir_path, MAX_PATH_LEN - 1);
            watches[*watch_count].path[MAX_PATH_LEN - 1] = '\0';
            (*watch_count)++;
        } else {
            printf("Warning: Maximum watch limit reached, cannot monitor %s\n", dir_path);
            inotify_rm_watch(inotify_fd, wd);
            return -1;
        }
    } else {
        printf("Warning: Failed to add watch for %s: %s\n", dir_path, strerror(errno));
        errors++;
    }
    
    dir = opendir(dir_path);
    if (dir == NULL) {
        printf("Warning: Cannot open directory %s for recursive watching: %s\n", 
               dir_path, strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (is_dot_entry(entry->d_name)) {
            continue;
        }
        
        safe_path_join(full_path, sizeof(full_path), dir_path, entry->d_name);
        
        if (lstat(full_path, &statbuf) != 0) {
            printf("Warning: Cannot stat %s: %s\n", full_path, strerror(errno));
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            if (add_recursive_watches(inotify_fd, full_path, watches, watch_count) != 0) {
                errors++;
            }
        }
    }
    
    closedir(dir);
    return errors > 0 ? -1 : 0;
}

int end_backup(const char *source, char targets[][MAX_PATH_LEN], int target_count) {
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
            
            if (matches == target_count && matches == active_backups[i].target_count) {
                for (int j = 0; j < active_backups[i].target_count; j++) {
                    pid_t pid = active_backups[i].monitor_pids[j];
                    if (kill(pid, SIGTERM) != 0) {
                        printf("Warning: Failed to terminate monitoring process %d: %s\n", 
                               pid, strerror(errno));
                    } else {
                        int status;
                        if (waitpid(pid, &status, 0) < 0) {
                            printf("Warning: Failed to wait for process %d: %s\n", 
                                   pid, strerror(errno));
                        }
                    }
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

int files_are_same(const char *file1, const char *file2) {
    struct stat stat1, stat2;
    
    if (stat(file1, &stat1) != 0 || stat(file2, &stat2) != 0) {
        return 0; 
    }
    
    return (stat1.st_size == stat2.st_size && stat1.st_mtime == stat2.st_mtime);
}

int sync_directories(const char *backup_dir, const char *original_dir) {
    DIR *backup_d, *original_d;
    struct dirent *entry;
    struct stat statbuf;
    char backup_path[MAX_PATH_LEN];
    char original_path[MAX_PATH_LEN];
    
    backup_d = opendir(backup_dir);
    if (backup_d == NULL) {
        printf("Error: Could not open backup directory %s: %s\n", backup_dir, strerror(errno));
        return -1;
    }
    
    while ((entry = readdir(backup_d)) != NULL) {
        if (is_dot_entry(entry->d_name)) {
            continue;
        }
        
        safe_path_join(backup_path, sizeof(backup_path), backup_dir, entry->d_name);
        safe_path_join(original_path, sizeof(original_path), original_dir, entry->d_name);
        
        if (lstat(backup_path, &statbuf) != 0) {
            continue;
        }
        
        if (S_ISDIR(statbuf.st_mode)) {
            if (!path_exists(original_path)) {
                if (create_directory_recursive(original_path) != 0) {
                    printf("Warning: Failed to create directory %s during restore\n", original_path);
                    continue;
                }
            }
            if (sync_directories(backup_path, original_path) != 0) {
                printf("Warning: Failed to sync subdirectory %s\n", backup_path);
            }
        } else {
            if (!path_exists(original_path) || !files_are_same(backup_path, original_path)) {
                printf("Restoring: %s\n", original_path);
                if (copy_file(backup_path, original_path) != 0) {
                    printf("Warning: Failed to restore file %s\n", original_path);
                }
            }
        }
    }
    closedir(backup_d);
    
    original_d = opendir(original_dir);
    if (original_d == NULL) {
        create_directory_recursive(original_dir);
        return 0;
    }
    
    while ((entry = readdir(original_d)) != NULL) {
        if (is_dot_entry(entry->d_name)) {
            continue;
        }
        
        safe_path_join(backup_path, sizeof(backup_path), backup_dir, entry->d_name);
        safe_path_join(original_path, sizeof(original_path), original_dir, entry->d_name);
        
        if (!path_exists(backup_path)) {
            printf("Removing: %s\n", original_path);
            if (is_directory(original_path)) {
                if (remove_directory_recursive(original_path) != 0) {
                    printf("Warning: Failed to remove directory %s during restore\n", original_path);
                }
            } else {
                if (unlink(original_path) != 0) {
                    printf("Warning: Failed to remove file %s during restore: %s\n", 
                           original_path, strerror(errno));
                }
            }
        }
    }
    closedir(original_d);
    
    return 0;
}

int restore_backup(const char *backup_path, const char *original_path) {
    if (!path_exists(backup_path)) {
        printf("Error: Backup directory '%s' does not exist\n", backup_path);
        return -1;
    }
    
    if (!is_directory(backup_path)) {
        printf("Error: Backup path '%s' is not a directory\n", backup_path);
        return -1;
    }
    
    printf("Restoring backup from %s to %s...\n", backup_path, original_path);
    
    if (!path_exists(original_path)) {
        if (create_directory_recursive(original_path) != 0) {
            printf("Error: Could not create original directory %s\n", original_path);
            return -1;
        }
    }
    
    if (sync_directories(backup_path, original_path) != 0) {
        printf("Error: Failed to restore backup\n");
        return -1;
    }
    
    return 0;
}

void cleanup_resources(void) {
    for (int i = 0; i < backup_count; i++) {
        for (int j = 0; j < active_backups[i].target_count; j++) {
            pid_t pid = active_backups[i].monitor_pids[j];
            if (kill(pid, SIGTERM) != 0) {
                printf("Warning: Failed to send SIGTERM to process %d: %s\n", 
                       pid, strerror(errno));
            } else {
                int status;
                if (waitpid(pid, &status, 0) < 0) {
                    printf("Warning: Failed to wait for process %d: %s\n", 
                           pid, strerror(errno));
                }
            }
        }
    }
}
