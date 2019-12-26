#include "../includes/inject.h"

#define OFFSETOF(struct, var) ((uintptr_t)(&((struct*)NULL)->var)

// Prepare registers for different archs
#ifdef MX64
    #define ip rip
    #define ax rax
    #define sp rsp
    #define bp rbp
    #define orig_ax orig_rax
#else
    #define ax eax
    #define ip eip
    #define sp esp
    #define bp ebp
    #define orig_ax orig_eax
#endif

/*
 * call _ax
 * int3
 * nop (to make it aligned with sizeof(long) bytes for not corrupting our own
 * stack with the read/write data function)
 */

uint8_t shellcode_call[] = {0xFF, 0xD0, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90};
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

    if (file_maps != NULL)
        fclose(file_maps);
ret:
    return;
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
        ERR("Couldn't find symbol %s in shared lib %s in current process\n",
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
        ERR("Couldn't find shared lib %s in pid: %i\n", lm->l_name, pid);
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
 * Read data to the remote process
 * Actually it is a size of ptr
 */

int read_data(pid_t pid, ptr_u_t addr, size_t size, ptr_u_t out)
{
    long ret;
    ptr_u_t ptr;

    while (size != 0)
    {
        size -= sizeof(ptr_t);
        ptr.ui = addr.ui + size;

        ret = ptrace(PTRACE_PEEKDATA, pid, ptr.p, 0);

        if (errno != 0 && ret == -1)
        {
            printf("    PTRACE_PEEKDATA failed on pid %i error: %s\n",
                   pid,
                   strerror(errno));
            return 0;
        }

#ifdef MX64
        printf("    Reading data %p + %zd -> 0x%016lX\n",
               addr.p,
               size,
               *(uintptr_t*)&ret);
#else
        printf("    Reading data %p + %zd -> 0x%08X\n",
               addr.p,
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

    while (size != 0)
    {
        size -= sizeof(ptr_t);
        ptr.ui = addr.ui + size;
        ptr_out.ui = out.ui + size;

#ifdef MX64
        printf("    Writing data %p + %zd -> 0x%016lX\n",
               out.p,
               size,
               *(uintptr_t*)ptr.p);

#else
        printf("    Writing data %p + %zd -> 0x%08X\n",
               out.p,
               size,
               *(uintptr_t*)ptr.p);

#endif
        ret = ptrace(PTRACE_POKEDATA, pid, ptr_out.p, *(ptr_t*)ptr.p);

        if (ret == -1 && errno != 0)
        {
            printf("    PTRACE_POKEDATA failed on pid %i error: %s\n",
                   pid,
                   strerror(errno));
            return 0;
        }
    }

    return 1;
}

ptr_t remote_dlopen(pid_t pid, const char* lib, int flags)
{
    struct user_regs_struct oldregs, regs;
    size_t sizeof_instr_to_wr = sizeof(shellcode_call);
    unsigned char backup_instructions[sizeof_instr_to_wr];
    ptr_u_t data, out, remote_dlopen_addr;
    int status;
    uintptr_t remote_filename_addr;
    int lib_len;

#ifndef MX64
    unsigned char stack_arguments[sizeof(flags) + sizeof(ptr_t)];
#endif

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

    if (WIFSTOPPED(status))
    {
        printf("Done on pid %i with signal %s (ip: %p ax: %p orig_ax: %p)\n",
               pid,
               strsignal(WSTOPSIG(status)),
               (ptr_t)oldregs.ip,
               (ptr_t)oldregs.ax,
               (ptr_t)oldregs.orig_ax);
    }

    // Let's see if we entered into a syscall.
    if (oldregs.orig_ax != (uintptr_t)-1)
    {
        // Let's do singlesteps until we're outside of the system call.
        // We know that we are outside of it when AX is not equal to 0
        // (We hope that it gets modified inside a wrapper of the syscall
        // function; but might not always work)
        // and ORG_AX == -1
        while (!(oldregs.ax != 0 && oldregs.orig_ax == (uintptr_t)-1))
        {
            printf("Single-stepping (trying to get out of a syscall)\n");

            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            // Wait for the single step
            waitpid(pid, &status, 0);
            // Get new registers.
            ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);

            if (WIFSTOPPED(status))
            {
                printf("Done on pid %i with signal %s (ip: %p ax: %p orig_ax: "
                       "%p)\n",
                       pid,
                       strsignal(WSTOPSIG(status)),
                       (ptr_t)oldregs.ip,
                       (ptr_t)oldregs.ax,
                       (ptr_t)oldregs.orig_ax);
            }
        }
    }

    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    printf("Got regs (ip: %p) on pid %i\n", (ptr_t)regs.ip, pid);

    printf("Reserving some memory on stack for filename on pid %i\n", pid);

    // Reserve some space for filename.
    lib_len = strlen(lib) + 1;
    
    lib_len -= (lib_len % sizeof(uintptr_t));
    lib_len += sizeof(uintptr_t);

    char tmp_filename[lib_len];
    strcpy(tmp_filename, lib);

    regs.sp -= lib_len;

    out.ui = regs.sp;
    data.p = (ptr_t)tmp_filename;

    // Write filename to the stack
    write_data(pid, data, lib_len, out);

    printf("Wrote filename %p on pid %i\n", (ptr_t)regs.sp, pid);

    remote_filename_addr = regs.sp;

#ifdef MX64

    regs.rdi = remote_filename_addr;
    regs.rsi = (uintptr_t)flags;

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

#endif

    regs.ax = remote_dlopen_addr.ui;

    out.p = backup_instructions;
    data.ui = regs.ip;

    printf("Reading current on instructions on ip address on pid %i\n", pid);

    // Backup next instructions from the current address of the instruction
    // pointer
    read_data(pid, data, sizeof_instr_to_wr, out);

    // Write shellcode
    out.ui = regs.ip;
    data.p = shellcode_call;

    printf("Writing instructions for dlopen call on pid %i\n", pid);

    write_data(pid, data, sizeof_instr_to_wr, out);

    printf("Executing shellcode on pid %i\n", pid);

    printf("    IP: %p\n", (ptr_t)regs.ip);

    // Set new registers.
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

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

    printf("    IP: %p\n", (ptr_t)regs.ip);

    out.ui = oldregs.ip;
    data.p = backup_instructions;

    // Write back the backed up instructions
    write_data(pid, data, sizeof_instr_to_wr, out);

    // Set up old registers back again
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

    // Detach process & let it continue like *nothing happened
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    // Get return value
    return (ptr_t)regs.ax;
}

int main(int cargs, char** args)
{
    pid_t pid;
    ptr_t lib_addr;

    if (cargs < 3)
    {
        printf("Arguments: <pid> <pathtoso>\n");
        return 0;
    }

    pid = atoi(args[1]);

    // Load library from remote process
    lib_addr = remote_dlopen(pid, args[2], RTLD_LAZY);

    if (lib_addr == NULL)
    {
        printf("Couldn't dlopen %s from pid %i\n", args[2], pid);
        return 0;
    }

    printf("Injected %s on pid %i at address %p\n", args[2], pid, lib_addr);

    return 1;
}
