# Project Development Stages

This directory contains the backup management system broken down into four development stages, representing a month of progressive development.

## Stage 1: Program Framework + Basic Commands

**Deadline: Week 1**

**What's implemented:**
- Basic program structure with command loop
- Command parsing (simple version, no quotes yet)
- Commands: `help`, `exit`
- Draft commands: `add`, `end`, `list`, `restore` (print "not implemented yet")
- `backup_info_t` structure and `active_backups` array (without monitoring)
- `create_directory_recursive()` helper function

**What's missing:**
- Quote support in command parsing
- Actual backup functionality
- File operations
- Monitoring

**To compile and test:**
```bash
cd stage1
gcc -Wall -Wextra -std=c99 -o backup_manager backup_manager.c
./backup_manager
```

## Stage 2: Initial Backup Without Monitoring

**Deadline: Week 2**

**What's implemented:**
- Full command parsing with quote support
- `add` command:
  - Validates source exists and is a directory
  - Validates target (empty or doesn't exist)
  - Performs initial directory copy using `copy_file()` and `copy_directory_recursive()`
- `list` command: shows source + targets
- `end` command: deactivates backup entry (no process management yet)
- Complete file copying functionality
- Symbolic link handling

**What's missing:**
- inotify monitoring
- Process management
- Recursive directory watching
- Restore functionality
- "Cannot back up into itself" check (can be added later)

**To compile and test:**
```bash
cd stage2
gcc -Wall -Wextra -std=c99 -o backup_manager backup_manager.c
./backup_manager
```

## Stage 3: Basic Monitoring via inotify (Simplified)

**Deadline: Week 3**

**What's implemented:**
- `add` command now launches `monitor_directory()` child process
- `monitor_directory()`:
  - Creates its own `inotify_fd` instance
  - Adds watch to source root directory
  - Processes basic events: `IN_CREATE`, `IN_DELETE`, `IN_MODIFY`
  - Copies files/directories on create/modify
  - Removes files on delete
- `end` command: terminates child process via `kill()` + `waitpid()`
- `cleanup_resources()`: kills all remaining processes on exit
- Signal handling for graceful shutdown

**What's missing:**
- Recursive subdirectory watching (only root directory watched)
- Multiple target support (only first target monitored)
- `IN_MOVED_FROM` / `IN_MOVED_TO` events
- Proper directory deletion handling
- Restore functionality

**Limitations:**
- Only monitors root directory, not subdirectories
- Only monitors first target if multiple targets specified
- Directory deletion not fully handled

**To compile and test:**
```bash
cd stage3
gcc -Wall -Wextra -std=c99 -D_GNU_SOURCE -o backup_manager backup_manager.c
./backup_manager
```

## Stage 4: Final Version

**Deadline: Week 4 (Final)**

**What's implemented:**
- **Multiple targets per source**: Each target has its own monitoring process
- **Recursive directory watching**: `add_recursive_watches()` watches all subdirectories
- **Complete event handling**: `IN_CREATE`, `IN_DELETE`, `IN_MODIFY`, `IN_MOVED_FROM`, `IN_MOVED_TO`
- **Robust path checking**: "target inside source" prevention
- **Smart restore**:
  - Copies only changed files (compares size and modification time)
  - Deletes files from original that don't exist in backup
- **Complete resource management**: Proper cleanup of all processes and file descriptors
- **Enhanced error handling**: Better error messages with context
- **Helper functions**: `is_dot_entry()`, `safe_path_join()` for code clarity

**Features:**
- Full recursive directory monitoring from the start
- Watch descriptor to path mapping for nested directories
- Proper handling of all file system events
- Intelligent restore with change detection
- Comprehensive error handling and logging

**To compile and test:**
```bash
cd stage4
gcc -Wall -Wextra -std=c99 -D_GNU_SOURCE -o backup_manager backup_manager.c
./backup_manager
```

## Development Timeline

```
Week 1: Stage 1 - Framework and interface
Week 2: Stage 2 - Offline backup system
Week 3: Stage 3 - Basic inotify monitoring
Week 4: Stage 4 - Full implementation with all features
```

## Notes

- Each stage builds naturally on the previous one
- Code shows realistic progression with incremental improvements
- Some limitations in early stages are intentional (e.g., no recursive watching in Stage 3)
- Final stage represents the complete, production-ready implementation
