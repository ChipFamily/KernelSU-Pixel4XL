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

def insert_after_brace(content, func_marker, insertion):
    """Insert after the opening brace of a function."""
    idx = content.find(func_marker)
    if idx == -1:
        return content, False
    brace = content.find('\n{', idx)
    if brace == -1:
        return content, False
    return content[:brace+2] + insertion + content[brace+2:], True

def insert_after_declarations(content, func_marker, insertion):
    """
    Insert after the last variable declaration in a function body.
    C90 rule: all declarations must come before any code.
    We find the first line that is NOT a declaration after the opening brace.
    """
    idx = content.find(func_marker)
    if idx == -1:
        return content, False
    brace = content.find('\n{', idx)
    if brace == -1:
        return content, False

    # Walk line by line from after the opening brace
    pos = brace + 2  # skip past '\n{'
    lines = content[pos:].split('\n')
    decl_end = pos
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Empty lines or pure declarations (type varname;)
        if stripped == '' or stripped == '{' or stripped == '}':
            decl_end = pos + sum(len(l)+1 for l in lines[:i+1])
            continue
        # If line starts with a type keyword or is a declaration, skip
        # Declaration heuristic: contains ';' and no '=' assignment that looks like code
        # Stop when we hit the first non-declaration code line
        is_decl = (
            stripped.startswith('const ') or
            stripped.startswith('struct ') or
            stripped.startswith('unsigned ') or
            stripped.startswith('int ') or
            stripped.startswith('long ') or
            stripped.startswith('char ') or
            stripped.startswith('void ') or
            stripped.startswith('bool ') or
            stripped.startswith('u32 ') or
            stripped.startswith('u64 ') or
            stripped.startswith('loff_t ') or
            stripped.startswith('size_t ') or
            stripped.startswith('ssize_t ')
        )
        if is_decl and ';' in stripped:
            decl_end = pos + sum(len(l)+1 for l in lines[:i+1])
        elif stripped == '':
            continue
        else:
            break

    return content[:decl_end] + insertion + content[decl_end:], True

def patch_file_after_brace(path, check_marker, decl, hook_marker, hook):
    """Patch file inserting hook immediately after opening brace (for functions with no local vars before hook point)."""
    with open(path, 'r') as f:
        src = f.read()
    if check_marker in src:
        print(f"{path}: already patched, skipping")
        return
    src, ok1 = insert_before(src, hook_marker, decl)
    src, ok2 = insert_after_brace(src, hook_marker, hook)
    with open(path, 'w') as f:
        f.write(src)
    print(f"{path}: decl={ok1}, hook={ok2}")

def patch_file_after_decls(path, check_marker, decl, hook_marker, hook):
    """Patch file inserting hook after variable declarations (for C90 compliance)."""
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
# do_execveat_common: hook goes after opening brace, before first local var
# but exec.c uses C99 so position after brace is fine
patch_file_after_brace(
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
# faccessat/do_faccessat: has local variable declarations - must insert AFTER them
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
# vfs_read: insert after declarations
patch_file_after_decls(
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
# input_handle_event: insert after opening brace
patch_file_after_brace(
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
patch_file_after_brace(
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
