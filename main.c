#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <security/audit/audit_ioctl.h>
#include <bsm/libbsm.h>
#include <libproc.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "uthash.h"

struct AuditEntry
{
    char path[MAXPATHLEN];
    int pid;
    int userId;
    int type;
};

struct ProcessInfo
{
    int pid;
    char processPath[PROC_PIDPATHINFO_MAXSIZE];
    UT_hash_handle hh; /* makes this structure hashable */
};

struct ProcessInfo *processes = NULL;

void updateProcess(int pid)
{
    struct ProcessInfo *p = NULL;
    char processPath[PROC_PIDPATHINFO_MAXSIZE];
    memset(processPath, 0, sizeof(processPath));
    if (proc_pidpath(pid, processPath, sizeof(processPath)) <= 0)
    {
        return;
    }

    HASH_FIND_INT(processes, &pid, p);
    if (NULL == p)
    {
        p = (struct ProcessInfo*)malloc(sizeof(struct ProcessInfo));
        memset(p, 0, sizeof(struct ProcessInfo));
        p->pid = pid;
        HASH_ADD_INT(processes, pid, p);
    }
    
    strcpy(p->processPath, processPath);
}

const char* getProcessName(int pid)
{
    struct ProcessInfo *p = NULL;

    HASH_FIND_INT(processes, &pid, p);

    if (NULL != p)
    {
        return p->processPath;
    }

    return NULL;
}


int main(int argc, char** argv)
{
    const char* pipePath = "/dev/auditpipe";

    if (argc < 2)
    {
        printf("Enter an argument to filter");
        return 0;
    }

    const char* filter = argv[1];
    printf("Watching:%s\n", filter);

    FILE* pipeFile = fopen(pipePath, "r");
    int fd = fileno(pipeFile);

    if (fd < 0)
    {
        fprintf(stderr, "Could not open pipe!\n");

        return 1;
    }

    int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode) < 0)
    {
        fprintf(stderr, "Error: AUDITPIPE_SET_PRESELECT_MODE\n");
    }

    int queueLength = 0;
    if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &queueLength) < 0)
    {
        fprintf(stderr, "Error: AUDITPIPE_GET_QLIMIT_MAX\n");
    }

    if (ioctl(fd, AUDITPIPE_SET_QLIMIT, &queueLength) < 0)
    {
        fprintf(stderr, "Error: AUDITPIPE_SET_QLIMIT\n");
    }

    u_int mask = 0xFFFFFFFF;
    
    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &mask) < 0)
    {
        fprintf(stderr, "Error: AUDITPIPE_SET_PRESELECT_FLAGS\n");
    }

    if (ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &mask) < 0)
    {
        fprintf(stderr, "Error: AUDITPIPE_SET_PRESELECT_NAFLAGS\n");
    }

    while (1)
    {
        u_char* buffer = NULL;

        int position = 0;
        int length = au_read_rec(pipeFile, &buffer);

        struct AuditEntry entry;
        memset(&entry, 0, sizeof(struct AuditEntry));
        

        while (length > 0)
        {
            tokenstr_t token;

            if (au_fetch_tok(&token, buffer + position, length) < 0)
            {
                break;
            }

            switch (token.id)
            {
                case AUT_HEADER32:
                case AUT_HEADER32_EX:
                case AUT_HEADER64:
                case AUT_HEADER64_EX:
                entry.type = token.tt.hdr32.e_type;
                break;
                case AUT_SUBJECT32:
                case AUT_SUBJECT32_EX:
                case AUT_SUBJECT64:
                case AUT_SUBJECT64_EX:
                entry.pid = token.tt.subj32.pid;
                entry.userId = token.tt.subj32.ruid;
                updateProcess(entry.pid);
                break;
                case AUT_PATH:
                strcpy(entry.path, token.tt.path.path);
                break;
            }

            position += token.len;
            length -= token.len;
        }

        free(buffer);

        if (strstr(entry.path, filter) != NULL)
        {
            printf("path:%s action:%d process:%d(%s)\n", entry.path, entry.type, entry.pid, getProcessName(entry.pid));
        }
    }

    fclose(pipeFile);
    return 0;
}