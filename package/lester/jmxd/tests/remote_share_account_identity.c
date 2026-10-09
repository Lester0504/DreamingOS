/* NSS fixture only: identity mutations stay in the test's /tmp directory. */
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <shadow.h>
#ifndef FS_TEST_DIRECTORY
#error FS_TEST_DIRECTORY_required
#endif
struct passwd *fs_test_getpwnam(const char *name)
{
    FILE *f=fopen(FS_TEST_DIRECTORY "/passwd","r");
    struct passwd *entry=NULL;
    if(!f)return NULL;
    while((entry=fgetpwent(f)) && strcmp(entry->pw_name,name)) {}
    fclose(f);return entry;
}
struct spwd *fs_test_getspnam(const char *name)
{
    FILE *f=fopen(FS_TEST_DIRECTORY "/shadow","r");
    struct spwd *entry=NULL;
    if(!f)return NULL;
    while((entry=fgetspent(f)) && strcmp(entry->sp_namp,name)) {}
    fclose(f);return entry;
}
