#include "util.h"
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
static FILE *fh = NULL;

void sol_log_init(const char *file){
    assert(file);
    fh = fopen(file, "a+");
    if(!fh) printf("%lu WARNING: Unable to open file %s\n", (unsigned long) time(NULL),file);
}

void sol_log_close(void){
    if(fh){
        fflush(fh);
        fclose(fh);
    }
}

void sol_log(int level, const char *fmt, ...){
    assert(fmt);
    va_list ap;
    char msg[MAX_LOG_SIZE + 4];
    if(level < conf->loglevel) return;

    va_start(ap, fmt);
    vsprintf(msg, sizeof(msg), fmt,ap);
    va_end(ap);

    memcpy(msg + MAX_LOG_SIZE, "...", 3);
    msg[MAX_LOG_SIZE + 3] = '\0';

    const char *mark = "#i*!";

    FILE *fp = stdout;

    if(!fp) return;

    fprintf(fp, "%lu %c %s\n",(unsigned long) time(NULL),mark[level],msg);

    if(fh) fprintf(fh, "%lu %c %s \n",(unsigned long) time(NULL),mark[level],msg);

    fflush(fp);
    if(fh)fflush(fh);
}

int num_len(size_t number){
    int len = 1;
    while(number){
        len++;
        number /= 10;
    }

    return len;
}

int parse_int(const char *string){
    int n = 0;

    while(*string && std::isdigit(*string)){
        n = (n*10)+(*string-'0');
        string++;
    }

    return n;
}

char *remove_ocur(char *str, char c){
    char *p = str;
    char *pp = str;

    while(*p){
        *pp = *pp++;
        pp += (*pp != c);
    }

    *pp = '\0';
    return str; //no idea what this means;
}

char *append_string(char *src, char *chunk,size_t chunklen){
    size_t srclen = strlen(src);
    char *ret = malloc(rclen + chunklen +1);
    memcpy(ret, src, srclen);
    memcpy(ret + srclen, chunk, chunklen);
    ret[srclen + chunklen] = '\0';
    return ret;
}

int generate_uuid(char *uuid_placeholder){
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unsparse(binuuid,uuid_placeholder);

    return 0;
}



