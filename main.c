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

struct EventInfo
{
    int id;
    char name[128];
    UT_hash_handle hh; /* makes this structure hashable */
};

struct ProcessInfo *processes = NULL;
struct EventInfo *eventNames = NULL;

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

const char* getEventName(int id)
{
    struct EventInfo *e = NULL;

    HASH_FIND_INT(eventNames, &id, e);

    if (NULL != e)
    {
        return e->name;
    }

    return NULL;
}

void parseEventNames(int printOnly)
{
    FILE* auditEventsFile = fopen("/etc/security/audit_event", "r");

    if (auditEventsFile)
    {
        char part[512];
        char lineBuffer[512];
        memset(part, 0, sizeof(part));
        memset(lineBuffer, 0, sizeof(lineBuffer));
        while (fgets(lineBuffer, sizeof(lineBuffer), auditEventsFile))
        {
            char* begin = lineBuffer;
            char* end = strchr(begin, ':');

            if (end)
            {
                int length = end - begin;
                if (length > 0)
                {
                    strncpy(part, begin, length);
                    part[length] = 0;
                    int id = 0;
                    if (sscanf(part, "%d", &id) > 0)
                    {
                        begin = end + 1;

                        end = strchr(begin, ':');
                        length = end - begin;
                        if (length > 0)
                        {
                            strncpy(part, begin, length);
                            part[length] = 0;

                            if (printOnly)
                            {
                                printf("%d: %s\n", id, part);
                            }
                            else
                            {
                                struct EventInfo *e = NULL;
                                HASH_FIND_INT(eventNames, &id, e);
                                if (NULL == e)
                                {
                                    e = (struct EventInfo*)malloc(sizeof(struct EventInfo));
                                    memset(e, 0, sizeof(struct EventInfo));
                                    e->id = id;
                                    strcpy(e->name, part);
                                    HASH_ADD_INT(eventNames, id, e);
                                }
                            }
                        }
                    }
                }
                
            }
            
            memset(part, 0, sizeof(part));
            memset(lineBuffer, 0, sizeof(lineBuffer));
        }
        
        fclose(auditEventsFile);
    }
}

void printUsage(const char* name)
{
    printf("Usage:  %s [-p pid | process_name] [-e event_id] path_filter\n", name);
    printf("        %s -l\n", name);
    printf("Arguments:\n");
    printf("\t-p pid | process_name      Filter by process id if it is a number otherwise process_name.\n");
    printf("\t-e event_id                Filter by event_id.\n");
    printf("\t-l                         List event id and names.\n");
}

void parseArgs(int argc, char** argv, int* eventFilter, int* pidFilter, char* processFilter, char* pathFilter)
{
    int ret_option = 0;
    while ((ret_option = getopt (argc, argv, ":p:e:l")) != -1)
    {
        switch (ret_option)
        {
            case 'l':
                parseEventNames(1);
                exit(0);
            break;
            case 'p':
                if (optarg == NULL || (optarg && optarg[0] == '-'))
                {
                    printf("error: missing argument for -p\n");
                    printUsage(argv[0]);
                    exit(1);
                }
                else
                {
                    //try integer parse first for pid
                    if (sscanf(optarg, "%d", pidFilter) > 0)
                    {
                        printf("Using pid %d for process filtering.\n", *pidFilter);
                    }
                    else
                    {
                        strcpy(processFilter, optarg);
                        printf("Using name '%s' for process filtering.\n", processFilter);
                    }
                }
            break;
            case 'e':
                if (optarg == NULL || (optarg && optarg[0] == '-'))
                {
                    printf("error: missing argument for -e\n");
                    printUsage(argv[0]);
                    exit(1);
                }
                else
                {
                    if (sscanf(optarg, "%d", eventFilter) > 0)
                    {
                        printf("Using %d for event filtering.\n", *eventFilter);
                    }
                    else
                    {
                        printf("error: missing event_id number for -e\n");
                        printUsage(argv[0]);
                        exit(1);
                    }
                }
            break;
            case ':':
                printf("error: missing argument for -%c\n", optopt);
                printUsage(argv[0]);
                exit(1);
            break;
            case '?':
                printf("error: unknown argument -%c\n", optopt);
                printUsage(argv[0]);
                exit(1);
            break;
            default:
            
            break;
        }
    }

    if (optind < argc)
    {
        strcpy(pathFilter, argv[optind]);
        printf("Using '%s' for path filtering.\n", pathFilter);
    }
    else
    {
        printf("error: missing argument path_filter\n");
        printUsage(argv[0]);
        exit(1);
    }
    
}


int main(int argc, char** argv)
{
    int eventFilter = 0;
    int pidFilter = 0;
    char processFilter[64];
    char pathFilter[128];
    memset(processFilter, 0, sizeof(processFilter));
    memset(pathFilter, 0, sizeof(pathFilter));

    parseArgs(argc, argv, &eventFilter, &pidFilter, processFilter, pathFilter);

    const char* pipePath = "/dev/auditpipe";

    if (argc < 2)
    {
        printf("Enter an argument to filter");
        return 0;
    }

    parseEventNames(0);

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

        if (strstr(entry.path, pathFilter) != NULL)
        {
            int print = 1;

            const char * processName = getProcessName(entry.pid);
            
            if (pidFilter > 0 && pidFilter != entry.pid)
            {
                print = 0;
            }
            else if (eventFilter > 0 && eventFilter != entry.type)
            {
                print = 0;
            }
            else if (processFilter[0] != 0 && strstr(processName, processFilter) == NULL)
            {
                print = 0;
            }

            if (print)
            {
                printf("path:%s event:%s(%d) process:%s(%d)\n", entry.path, getEventName(entry.type), entry.type, processName, entry.pid);
            }
        }
    }

    fclose(pipeFile);
    return 0;
}