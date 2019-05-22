#include "../includes/inject.h"

#define OFFSETOF(struct, var) ((uintptr_t)(&((struct*)NULL)->var))

// Prepare registers for different archs
#ifdef MX64
#define ip rip
#define ax rax
#define sp rsp
#else
#define ax eax
#define ip eip
#define sp esp
#endif

/*
 * call _ax
 * int3
 * nop (to make it aligned with sizeof(long) bytes for not corrupting our own
 * stack with the read/write data function)
 */

uint8_t shellcode_call[] = {0xFF, 0xD0, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90};
uintptr_t g_page_size;
const int str_hex_digits = sizeof(ptr_t) * 2;

void setup_string(string_t* str, size_t maxlen)
{
    str->len = 0;
    str->maxlen = maxlen;
    str->pc = (char*)malloc(maxlen);
    memset(str->pc, 0, maxlen);
}

void free_string(string_t* str)
{
    free(str->pc);
}

// Parse proc/pid/maps
void get_remote_lib(const char* lib, pid_t pid, lib_t* result)
{
    // Who knows maybe some actual path makes it that far...
    char maps[FILENAME_MAX], line_buffer[FILENAME_MAX + 0x100];
    char str_base[str_hex_digits + 1];
    int count_hex;
    FILE* file_maps;

    file_maps = NULL;
    result->base_addr.p = NULL;
    sprintf(maps, "/proc/%i/maps", pid);
    file_maps = fopen(maps, "r");

    if (file_maps == NULL)
    {
        goto ret;
    }

    // Find the first occurence, it's usually the base address of the library.
    while (fgets(line_buffer, sizeof(line_buffer), file_maps))
    {
        count_hex = 0;

        // Is that our library?
        if (strstr(line_buffer, lib))
        {
            memcpy(str_base, line_buffer, str_hex_digits);

            // Count hex digits on the first line to get its base address.
            while (str_base[count_hex] != '-' && count_hex < str_hex_digits)
            {
                count_hex++;
            }

            str_base[count_hex] = '\0';

            // Convert it into a pointer
#ifndef MX64
            result->base_addr.ui = strtoul(str_base, NULL, 16);
#else
            result->base_addr.ui = strtoull(str_base, NULL, 16);
#endif
            // Find where the filename of the library starts inside the line.
            while (line_buffer[count_hex] != '\n')
            {
                // We found a path here;
                if (line_buffer[count_hex] == '/')
                {
                    break;
                }

                count_hex++;
            }

            // We can just copy as the path is the last thing we get on the
            // line.
            strcpy(result->filename.pc, &line_buffer[count_hex]);
            result->filename.len = strlen(result->filename.pc);
            result->filename.len--;

            // Override \n.
            result->filename.pc[result->filename.len] = '\0';
            break;
        }
    }

ret:
    if (file_maps != NULL)
        fclose(file_maps);
}

ptr_u_t find_remote_sym(link_map_t* lm, const char* sym, pid_t pid)
{
    ptr_u_t result, ptr_sym, ptr_offset;
    lib_t remote_lib, local_lib;
    setup_string(&remote_lib.filename, FILENAME_MAX);
    setup_string(&local_lib.filename, FILENAME_MAX);

    // Sometimes they're just symbolic names.
    realpath(lm->l_name, local_lib.filename.pc);

    result.p = NULL;

    // Find its symbol so we can calculate its offset
    ptr_sym.p = dlsym(lm, sym);

    if (ptr_sym.p == NULL)
    {
        ERR("couldn't find symbol %s in shared lib %s in current process\n",
            sym,
            lm->l_name);
        goto ret;
    }

    // Now we can calculate its offset between the base address of the library &
    // symbol
    ptr_offset.ui = ptr_sym.ui - lm->l_addr;

    // Find now the address from our targeted pid
    get_remote_lib(local_lib.filename.pc, pid, &remote_lib);

    if (remote_lib.base_addr.p == NULL)
    {
        ERR("couldn't find shared lib %s in pid: %i\n", lm->l_name, pid);
        goto ret;
    }

    // Now we can calculate the exact address for our remote process with the
    // offset calculated previously
    result.ui = remote_lib.base_addr.ui + ptr_offset.ui;

ret:

    free_string(&remote_lib.filename);
    free_string(&local_lib.filename);

    return result;
}

// TODO: There is still a case where the remote process haven't the library
// loaded.. So we can just use this function to get dlopen and load our libs on
// the remote process!

ptr_u_t get_remote_sym(const char* lib, const char* sym, pid_t pid)
{
    link_map_t* lm;
    ptr_u_t result;
    lib_t remote_lib;

    setup_string(&remote_lib.filename, FILENAME_MAX);

    result.p = NULL;

    // Try to open this way first
    lm = (link_map_t*)dlopen(lib, RTLD_LAZY);

    if (lm == NULL)
    {
        lm = (link_map_t*)dlopen(NULL, RTLD_LAZY);

        // Ignore the current process, it's the first into the list.
        dlclose(lm);

        lm = lm->l_next;

        while (lm != NULL)
        {
            // Find our library
            if (lib != NULL)
            {
                if (!strstr(lm->l_name, lib))
                    goto next;
            }

            // If yes then we load it and find its address into the remote
            // process.
            lm = (link_map_t*)dlopen(lm->l_name, RTLD_LAZY);
            result = find_remote_sym(lm, sym, pid);

            // Close it once we're done
            dlclose(lm);

            if (result.p != NULL)
            {
                goto ret;
            }

        // Go on next module loaded otherwhise
        next:
            lm = lm->l_next;
        }
    }
    else
    {
        // We found it on the first try!
        result = find_remote_sym(lm, sym, pid);
        dlclose(lm);
    }

    // Library isn't loaded..
    // We might load it ourselves and try to find it again.
    if (lib != NULL)
    {
        get_remote_lib(lib, pid, &remote_lib);

        if (remote_lib.base_addr.p == NULL)
        {
            // At this point, there is nothing we can do...
            ERR("Couldn't find %s(%s) from remote process...\n", lib, sym);
            goto ret;
        }

        // Okay this is good, now we load it for our current process
        // and we can extract the symbol address from remote process.
        lm = (link_map_t*)dlopen(remote_lib.filename.pc, RTLD_LAZY);

        if (lm != NULL)
        {
            result.p = dlsym(lm, sym);

            if (result.p == NULL)
            {
                ERR("Couldn't find %s(%s) from current process...\n", lib, sym);
                goto ret;
            }

            result.ui -= lm->l_addr;
            result.ui += remote_lib.base_addr.ui;
            dlclose(lm);
        }
        else
        {
            // Architecture is maybe not the same... Or something else.
            ERR("Couldn't load %s(%s) from to our process...\n", lib, sym);
            goto ret;
        }
    }

ret:
    free_string(&remote_lib.filename);

    return result;
}

/*
 * This is an old way to list all shared libraries from our current process
 */

static int list_shared_libs(struct dl_phdr_info* info,
                            size_t size,
                            ptr_t lib_infos_p)
{
    lib_t* curlib;
    lib_info_t* lib_infos;

    // Let's avoid our own process.
    if (*info->dlpi_name == '\0')
        goto ret;

    lib_infos = lib_infos_p;

    if (lib_infos->libs == NULL)
    {
        lib_infos->libs = malloc(sizeof(lib_t));
    }
    else
    {
        lib_infos->libs = realloc(lib_infos->libs,
                                  (lib_infos->count + 1) * sizeof(lib_t));
    }

    curlib = &lib_infos->libs[lib_infos->count];

    // Setup string for filename of library
    setup_string(&curlib->filename, FILENAME_MAX);

    // Get its base address
    curlib->base_addr.ui = info->dlpi_addr;

    // Copy filename & setup new length of the filename
    strcpy(curlib->filename.pc, info->dlpi_name);
    curlib->filename.len = strlen(curlib->filename.pc);

    // Iterate the number of shared libraries
    lib_infos->count++;

ret:
    return 0;
}

ptr_u_t find_remote_sym_2(const char* sym, pid_t pid)
{
    ptr_u_t result;
    lib_info_t lib_infos;
    lib_t* curlib;
    int i;

    memset(&lib_infos, 0, sizeof(lib_info_t));

    result.p = NULL;

    dl_iterate_phdr(list_shared_libs, &lib_infos);

    for (i = 0; i < lib_infos.count; i++)
    {
        curlib = &lib_infos.libs[i];
        free_string(&curlib->filename);
    }

    free(lib_infos.libs);

    return result;
}

/*
 * This is another way to read/write to virtual process memory rather
 * than ptrace
 */

int read_data_2(pid_t pid, ptr_u_t addr, size_t size, ptr_u_t out)
{
    struct iovec local, remote;
    size_t nread;

    printf("process_vm_readv %p(%zd) -> pid %i\n", out.p, size, pid);

    local.iov_base = out.p;
    local.iov_len = size;
    remote.iov_base = addr.p;
    remote.iov_len = size;

    nread = process_vm_readv(pid, &local, 1, &remote, 1, 0);

    printf("Read %zd bytes\n", nread);

    // Success reading
    if (nread == size)
    {
        for (nread = 0LL; nread < size; nread++)
        {
            if (nread > 0 && nread % 16 == 0)
                printf("\n");

            printf("%02X ", *(unsigned char*)(out.ui + size));
        }

        printf("\n");

        return 1;
    }
    else
    {
        printf("process_vm_readv failed on pid %i, error: %s\n",
               pid,
               strerror(errno));

        return 0;
    }
}

int write_data_2(pid_t pid, ptr_u_t addr, size_t size, ptr_u_t out)
{
    struct iovec local, remote;
    size_t nwrite;

    printf("process_vm_writev %p(%zd) -> pid %i\n", out.p, size, pid);

    local.iov_base = addr.p;
    local.iov_len = size;
    remote.iov_base = out.p;
    remote.iov_len = size;

    nwrite = process_vm_writev(pid, &local, 1, &remote, 1, 0);

    printf("Wrote %zd bytes\n", nwrite);

    // Success writing
    if (nwrite == size)
    {
        for (nwrite = 0LL; nwrite < size; nwrite++)
        {
            if (nwrite > 0 && nwrite % 16 == 0)
                printf("\n");

            printf("%02X ", *(unsigned char*)(addr.ui + size));
        }

        printf("\n");

        return 1;
    }
    else
    {
        printf("process_vm_writev failed on pid %i, error: %s\n",
               pid,
               strerror(errno));

        return 0;
    }
}

/*
 * Read data to the remote process
 * Actually it is a size of ptr
 */

int read_data(pid_t pid, ptr_u_t addr, size_t size, ptr_u_t out)
{
    long ret;
    ptr_u_t ptr;

    while (size != 0LL)
    {
        size -= sizeof(ptr_t);
        ptr.ui = addr.ui + size;

        ret = ptrace(PTRACE_PEEKDATA, pid, ptr.p, 0);

        if (errno != 0 && ret == -1)
        {
            printf("PTRACE_PEEKDATA failed on pid %i error: %s\n",
                   pid,
                   strerror(errno));
            return 0;
        }

#ifdef MX64
        printf("Reading data %p + %zd -> 0x%016lX\n",
               out.p,
               size,
               *(uintptr_t*)&ret);
#else
        printf("Reading data %p + %zd -> 0x%08X\n",
               out.p,
               size,
               *(uintptr_t*)&ret);
#endif
        *(ptr_t*)(out.ui + size) = *(ptr_t*)&ret;
    }

    return 1;
}

/*
 * Write data to the remote process
 * Actually it is a size of ptr
 */

int write_data(pid_t pid, ptr_u_t addr, size_t size, ptr_u_t out)
{
    long ret;
    ptr_u_t ptr;
    ptr_u_t ptr_out;

    while (size != 0LL)
    {
        size -= sizeof(ptr_t);
        ptr.ui = addr.ui + size;
        ptr_out.ui = out.ui + size;

#ifdef MX64
        printf("Writing data %p + %zd -> 0x%016lX\n",
               out.p,
               size,
               *(uintptr_t*)ptr.p);

#else
        printf("Writing data %p + %zd -> 0x%08X\n",
               out.p,
               size,
               *(uintptr_t*)ptr.p);

#endif
        ret = ptrace(PTRACE_POKEDATA, pid, ptr_out.p, *(ptr_t*)ptr.p);

        if (ret == -1 && errno != 0)
        {
            printf("PTRACE_POKEDATA failed on pid %i error: %s\n",
                   pid,
                   strerror(errno));
            return 0;
        }
    }

    return 1;
}

ptr_t remote_mmap(pid_t pid,
                  ptr_t addr,
                  size_t size,
                  int prot,
                  int flags,
                  int fd,
                  __off_t offset)
{
#ifndef MX64
    // Reserve some space into the stack, mmap call have 6 arguments
    uintptr_t stack_arguments[6];
#endif

    struct user_regs_struct oldregs, regs;
    size_t bytes_to_write = sizeof(shellcode_call);
    uint8_t backup_data[bytes_to_write];
    ptr_u_t data, out, remote_mmap_addr;
    int status;

    // Let's find mmap first!
    remote_mmap_addr = get_remote_sym("libc", "mmap", pid);

    if (remote_mmap_addr.p == NULL)
    {
        printf("Couldn't find mmap address for pid %i\n", pid);
        return NULL;
    }

    printf("Found mmap address %p on pid %i\n", remote_mmap_addr.p, pid);

    // Attach to process we want to.
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, &status, 0);

    printf("Attached to %i\n", pid);

    // Obtain its current registers so we can set them back again
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    printf("Got regs (ip: %p) on pid %i\n", (ptr_t)regs.ip, pid);

#ifdef MX64

    // Setup arguments for calling mmap on remote process
    regs.rdi = (uintptr_t)addr;                                // addr
    regs.rsi = (((size - 1) / g_page_size) + 1) * g_page_size; // len
    regs.rdx = prot;                                           // prot
    regs.rcx = flags;                                          // flags
    regs.r8 = fd;     // file descriptor
    regs.r9 = offset; // offset
    regs.rax = remote_mmap_addr.ui;

#else

    // Arguments are passed through stack here.
    // Save up some space on stack to prepare our arguments
    regs.esp -= sizeof(stack_arguments);

    stack_arguments[0] = (uintptr_t)addr;                                // addr
    stack_arguments[1] = (((size - 1) / g_page_size) + 1) * g_page_size; // len
    stack_arguments[2] = prot;                                           // prot
    stack_arguments[3] = flags;  // flags
    stack_arguments[4] = fd;     // file descriptor
    stack_arguments[5] = offset; // offset

    regs.eax = remote_mmap_addr.ui;

    printf("Writing arguments on the stack %p on pid %i\n",
           (ptr_t)regs.esp,
           pid);

    out.ui = regs.esp;
    data.p = stack_arguments;

    // Write arguments to the stack
    write_data(pid, data, sizeof(stack_arguments), out);

#endif

    // Set the new registers
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // Backup instructions
    data.ui = regs.ip;
    out.p = backup_data;

    read_data(pid, data, bytes_to_write, out);

    printf("Data has been read for backing up instructions on pid %i\n", pid);

    // Write shellcode
    out.ui = regs.ip;
    data.p = shellcode_call;

    printf("Writing instructions for mmap call on pid %i\n", pid);

    write_data(pid, data, bytes_to_write, out);

    printf("Executing shellcode on pid %i\n", pid);

    // Continue execution & allocate memory with mmap syscall
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    printf("Waiting for pid %i\n", pid);

    // Wait for the breakpoint (interrupt 3)
    waitpid(pid, &status, 0);

    // Hopefully it did ran correctly!
    if (WIFSTOPPED(status))
    {
        printf("Done on pid %i with signal %s\n",
               pid,
               strsignal(WSTOPSIG(status)));
    }

    // Get registers again in order to get the return value
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // Set back the assembly instructions
    data.p = backup_data;
    out.ui = oldregs.ip;

    printf("Setting back old instructions at %p on pid %i\n", out.p, pid);

    write_data(pid, data, bytes_to_write, out);

    // Set up old registers back again
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

    printf("Detaching on pid %i\n", pid);

    // Detach process & let it continue like *nothing happened*
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Get return value
    return (ptr_t)regs.ax;
}

int remote_munmap(pid_t pid, ptr_t addr, size_t size)
{
#ifndef MX64
    // Reserve some space into the stack, mmap call have 6 arguments
    uintptr_t stack_arguments[2];
#endif

    struct user_regs_struct oldregs, regs;
    size_t bytes_to_write = sizeof(shellcode_call);
    uint8_t backup_data[bytes_to_write];
    ptr_u_t data, out, remote_munmap_addr;
    int status;

    // Let's find munmap first!
    remote_munmap_addr = get_remote_sym("libc", "munmap", pid);

    if (remote_munmap_addr.p == NULL)
    {
        printf("Couldn't find munmap address for pid %i\n", pid);
        return -1;
    }

    printf("Found munmap address %p on pid %i\n", remote_munmap_addr.p, pid);

    // Attach to process we want to.
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, &status, 0);

    printf("Attached to %i\n", pid);

    // Obtain its current registers so we can set them back again
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    printf("Got regs (ip: %p) on pid %i\n", (ptr_t)regs.ip, pid);

#ifdef MX64

    // Setup arguments for calling munmap on remote process
    regs.rdi = (uintptr_t)addr;                                // addr
    regs.rsi = (((size - 1) / g_page_size) + 1) * g_page_size; // len
    regs.rax = remote_munmap_addr.ui;

#else

    // Arguments are passed through stack here.
    // Save up some space on stack to prepare our arguments
    regs.esp -= sizeof(stack_arguments);

    stack_arguments[0] = (uintptr_t)addr;                                // addr
    stack_arguments[1] = (((size - 1) / g_page_size) + 1) * g_page_size; // len

    regs.eax = remote_munmap_addr.ui;

    printf("Writing arguments on the stack %p on pid %i\n",
           (ptr_t)regs.esp,
           pid);

    out.ui = regs.esp;
    data.p = stack_arguments;

    // Write arguments to the stack
    write_data(pid, data, sizeof(stack_arguments), out);

#endif

    // Set the new registers
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // Backup instructions
    data.ui = regs.ip;
    out.p = backup_data;

    read_data(pid, data, bytes_to_write, out);

    printf("Data has been read for backing up instructions on pid %i\n", pid);

    // Write shellcode
    out.ui = regs.ip;
    data.p = shellcode_call;

    printf("Writing instructions for munmap call on pid %i\n", pid);

    write_data(pid, data, bytes_to_write, out);

    printf("Executing shellcode on pid %i\n", pid);

    // Continue execution & allocate memory with munmap syscall
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    printf("Waiting for pid %i\n", pid);

    // Wait for the breakpoint (interrupt 3)
    waitpid(pid, &status, 0);

    // Hopefully it did ran correctly!
    if (WIFSTOPPED(status))
    {
        printf("Done on pid %i with signal %s\n",
               pid,
               strsignal(WSTOPSIG(status)));
    }

    // Get registers again in order to get the return value
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // Set back the assembly instructions
    data.p = backup_data;
    out.ui = oldregs.ip;

    printf("Setting back old instructions at %p on pid %i\n", out.p, pid);

    write_data(pid, data, bytes_to_write, out);

    // Set up old registers back again
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

    printf("Detaching on pid %i\n", pid);

    // Detach process & let it continue like *nothing happened*
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Get return value
    return *(int*)&regs.ax;
}

ptr_t remote_dlopen(pid_t pid,
                    const char* lib,
                    int flags,
                    ptr_t remote_addr_temp)
{
    char filename[PATH_MAX];
    struct user_regs_struct oldregs, regs;
    size_t bytes_to_write = sizeof(shellcode_call);
    ptr_u_t data, out, remote_dlopen_addr;
    int status;
    uintptr_t remote_filename_addr;

#ifndef MX64
    unsigned char stack_arguments[sizeof(flags) + sizeof(ptr_t)];
#endif

    strcpy(filename, lib);

    remote_dlopen_addr = get_remote_sym("libc", "__libc_dlopen_mode", pid);

    if (remote_dlopen_addr.p == NULL)
    {
        printf("Couldn't find dlopen on pid: %i\n", pid);
        return NULL;
    }

    printf("Found dlopen address %p on pid %i\n", remote_dlopen_addr.p, pid);

    // Attach to process we want to.
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    waitpid(pid, &status, 0);

    printf("Attached to %i\n", pid);

    // Obtain its current registers so we can set them back again
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    printf("Got regs (ip: %p) on pid %i\n", (ptr_t)regs.ip, pid);

// Might add an option to choose between stack or our allocated page
#ifdef false

    remote_filename_addr = (uintptr_t)remote_addr_temp;
    out.ui = remote_filename_addr;
    data.p = filename;

    write_data(pid, data, sizeof(filename), out);

    *(uintptr_t*)(&remote_addr_temp) += sizeof(filename);

#else

    regs.sp -= sizeof(filename);

    strcpy(filename, lib);

    out.ui = regs.sp;
    data.p = filename;

    // Write it to the stack
    write_data(pid, data, sizeof(filename), out);

    printf("Wrote filename %p on pid %i\n", (ptr_t)regs.sp, pid);

    remote_filename_addr = regs.sp;

#endif

#ifdef MX64

    regs.rdi = remote_filename_addr;
    regs.rsi = (uintptr_t)flags;
    regs.rax = remote_dlopen_addr.ui;

#else

    // Should be done this way:
    // push flags
    // push strlib
    // call eax
    // int3

    *(uintptr_t*)((uintptr_t)stack_arguments) = remote_filename_addr;
    *(int*)((uintptr_t)stack_arguments + sizeof(ptr_t)) = flags;

    regs.esp -= sizeof(stack_arguments);

    data.p = stack_arguments;
    out.ui = regs.esp;

    write_data(pid, data, sizeof(stack_arguments), out);

    regs.eax = remote_dlopen_addr.ui;

#endif

    regs.ip = (uintptr_t)remote_addr_temp;

    // Set the new registers
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    // Write shellcode
    out.p = remote_addr_temp;
    data.p = shellcode_call;

    printf("Writing instructions for dlopen call on pid %i\n", pid);

    write_data(pid, data, bytes_to_write, out);

    printf("Executing shellcode on pid %i\n", pid);

    // Continue execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    printf("Waiting for pid %i\n", pid);

    // Wait for the breakpoint (interrupt 3)
    waitpid(pid, &status, 0);

    // Hopefully it did ran correctly!
    if (WIFSTOPPED(status))
    {
        printf("Done on pid %i with signal %s\n",
               pid,
               strsignal(WSTOPSIG(status)));
    }

    // Get registers again in order to get the return value
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    // Set up old registers back again
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

    printf("Detaching on pid %i\n", pid);

    // Detach process & let it continue like *nothing happened*
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Get return value
    return (ptr_t)regs.ax;
}

int main(int cargs, char** args)
{
    pid_t pid;
    ptr_t lib_addr, remote_addr_temp;

    g_page_size = sysconf(_SC_PAGESIZE);

    if (cargs < 3)
    {
        printf("Not enourgh arguments, usage: ./inject <pid> <pathtoso>\n");
        return 0;
    }

    pid = atoi(args[1]);

    // Let's preallocate some memory for our shellcode
    remote_addr_temp = remote_mmap(pid,
                                          NULL,
                                          g_page_size,
                                          PROT_EXEC | PROT_WRITE | PROT_READ,
                                          MAP_PRIVATE | MAP_ANONYMOUS,
                                          -1,
                                          0);

    if (remote_addr_temp == NULL)
    {
        printf("Couldn't allocate memory from pid %i\n", pid);
        return 0;
    }

    // Load library from remote process
    lib_addr = remote_dlopen(pid, args[2], RTLD_LAZY, remote_addr_temp);

    if (lib_addr == NULL)
    {
        printf("Couldn't dlopen %s from pid %i\n", args[2], pid);
        goto failed_dlopen;
    }

    printf("Injected %s on pid %i at address %p\n", args[2], pid, lib_addr);

failed_dlopen:
    // Free memory previously allocated
    if (remote_munmap(pid, remote_addr_temp, g_page_size) == -1)
    {
        printf("Failed to free page %p from pid %i",
               remote_addr_temp,
               pid);

        return 0;
    }

    printf("Page on %p has been free'd from pid %i\n",
           remote_addr_temp,
           pid);

    return 1;
}
