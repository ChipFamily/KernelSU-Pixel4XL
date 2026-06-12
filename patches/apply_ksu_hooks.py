#!/usr/bin/env python3
"""
Apply KSU manual hooks to kernel source files.
Official non-GKI method per kernelsu.org/guide/how-to-integrate-for-non-gki.html
"""

def insert_before(content, marker, insertion):
    idx = content.find(marker)
    if idx == -1:
        return content, False
    return content[:idx] + insertion + content[idx:], True

def insert_after_declarations(content, func_marker, insertion):
    """
    Insert after the last variable declaration in a function body.
    C90 rule: all declarations must come before any code.
    """
    idx = content.find(func_marker)
    if idx == -1:
        return content, False
    # Find the opening brace of the function body
    brace = content.find('\n{', idx)
    if brace == -1:
        return content, False

    # Walk line by line from after the opening brace
    pos = brace + 2  # skip past '\n{'
    lines = content[pos:].split('\n')
    insert_pos = pos  # default: right after brace
    cumulative = pos

    for i, line in enumerate(lines):
        stripped = line.strip()
        line_end = cumulative + len(line) + 1  # +1 for \n

        if stripped == '':
            # empty line - keep scanning
            cumulative = line_end
            continue

        # Check if this looks like a variable declaration
        is_decl = any(stripped.startswith(t) for t in [
            'const ', 'struct ', 'unsigned ', 'int ', 'long ',
            'char ', 'void ', 'bool ', 'u8 ', 'u16 ', 'u32 ', 'u64 ',
            'loff_t ', 'size_t ', 'ssize_t ', 'pid_t ', 'uid_t ',
            'gid_t ', 'mode_t ', 'umode_t ', 'mm_segment_t ',
            'static ', 'register ',
        ])

        if is_decl and ';' in stripped and '(' not in stripped.split(';')[0]:
            # Looks like a declaration (not a function call ending in ;)
            insert_pos = line_end
            cumulative = line_end
        elif stripped.startswith('#'):
            # Preprocessor directive - skip
            cumulative = line_end
        else:
            # First non-declaration code line - insert before it
            break

        cumulative = line_end

    return content[:insert_pos] + insertion + content[insert_pos:], True

def patch_file(path, check_marker, decl, hook_marker, hook):
    with open(path, 'r') as f:
        src = f.read()
    if check_marker in src:
        print(f"{path}: already patched, skipping")
        return
    src, ok1 = insert_before(src, hook_marker, decl)
    src, ok2 = insert_after_declarations(src, hook_marker, hook)
    with open(path, 'w') as f:
        f.write(src)
    print(f"{path}: decl={ok1}, hook={ok2}")

# === fs/exec.c ===
patch_file(
    'fs/exec.c',
    'ksu_handle_execveat',
    '''
#ifdef CONFIG_KSU
extern bool ksu_execveat_hook __read_mostly;
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
\t\t\tvoid *envp, int *flags);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
\t\t\t\t void *argv, void *envp, int *flags);
#endif
''',
    'static int do_execveat_common(',
    '''
#ifdef CONFIG_KSU
\tif (unlikely(ksu_execveat_hook))
\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
\telse
\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);
#endif
'''
)

# === fs/open.c ===
with open('fs/open.c', 'r') as f:
    src = f.read()

if 'ksu_handle_faccessat' not in src:
    decl = '''
#ifdef CONFIG_KSU
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
\t\t\t int *flags);
#endif
'''
    hook = '''
#ifdef CONFIG_KSU
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
'''
    for marker in ['long do_faccessat(', 'SYSCALL_DEFINE3(faccessat,']:
        if marker in src:
            src, ok1 = insert_before(src, marker, decl)
            src, ok2 = insert_after_declarations(src, marker, hook)
            print(f"fs/open.c [{marker}]: decl={ok1}, hook={ok2}")
            break
    with open('fs/open.c', 'w') as f:
        f.write(src)
else:
    print("fs/open.c: already patched")

# === fs/read_write.c ===
patch_file(
    'fs/read_write.c',
    'ksu_handle_vfs_read',
    '''
#ifdef CONFIG_KSU
extern bool ksu_vfs_read_hook __read_mostly;
extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
\t\t\tsize_t *count_ptr, loff_t **pos);
#endif
''',
    'ssize_t vfs_read(',
    '''
#ifdef CONFIG_KSU
\tif (unlikely(ksu_vfs_read_hook))
\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif
'''
)

# === fs/stat.c ===
with open('fs/stat.c', 'r') as f:
    src = f.read()

if 'ksu_handle_stat' not in src:
    decl = '''
#ifdef CONFIG_KSU
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif
'''
    hook = '''
#ifdef CONFIG_KSU
\tksu_handle_stat(&dfd, &filename, &flags);
#endif
'''
    for fn in ['int vfs_statx(', 'int vfs_fstatat(']:
        if fn in src:
            src, ok1 = insert_before(src, fn, decl)
            src, ok2 = insert_after_declarations(src, fn, hook)
            print(f"fs/stat.c [{fn}]: decl={ok1}, hook={ok2}")
            break
    with open('fs/stat.c', 'w') as f:
        f.write(src)
else:
    print("fs/stat.c: already patched")

# === drivers/input/input.c ===
patch_file(
    'drivers/input/input.c',
    'ksu_handle_input_handle_event',
    '''
#ifdef CONFIG_KSU
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);
#endif
''',
    'static void input_handle_event(',
    '''
#ifdef CONFIG_KSU
\tif (unlikely(ksu_input_hook))
\t\tksu_handle_input_handle_event(&type, &code, &value);
#endif
'''
)

# === fs/devpts/inode.c ===
patch_file(
    'fs/devpts/inode.c',
    'ksu_handle_devpts',
    '''
#ifdef CONFIG_KSU
extern int ksu_handle_devpts(struct inode*);
#endif
''',
    'void *devpts_get_priv(',
    '''
#ifdef CONFIG_KSU
\tksu_handle_devpts(dentry->d_inode);
#endif
'''
)

print("=== All KSU hooks applied ===")
