/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
	return 0;
  } else {
    return NOUSER;
  }
}

int authenticate(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  // check if user exists
  if (p == NULL){
    return 0;
  } else {
    const char* input_Passwd = getpass("Password: "); // no echoing
    const char* encrypted_input_Passwd = crypt(input_Passwd, p->pw_passwd);

    // compare encrypted passwords
    if (strcmp(encrypted_input_Passwd, p->pw_passwd) == 0){
      return 1; 
    }
    return 0; 
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

int main(int argc, char **argv)
{
  char username[USERNAME_SIZE];
  
  /* 
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */
  while(1)
  {
    read_username(username);
    if (authenticate(username)) {
      printf("User authenticated successfully.\n");
      return 0; 
    } else {
      printf("Unknown user or incorrect password.\n");
    }
  }
}
  

  
