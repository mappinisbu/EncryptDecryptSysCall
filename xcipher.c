#include <asm/unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <openssl/md5.h>

#include "sys_xcrypt.h"

#define DIGEST_LEN = 16;

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif


void printDigest(unsigned char* digest) {
int i;
for (i = 0; i < 16; i++)
{
   printf("%02x", digest[i]);
}

printf("\n");
}


int printHelp()
{
    printf("xcipher Usage\n");
    printf("flag: -e to encrypt; -d to decrypt\n");
    printf("flag: -p ARG to specify the encryption/decryption key\n");
    printf("-h to provide a helpful usage message\n");
    printf("input file name\n");
    printf("output file name\n");
    printf(" Ex: ./xcipher -p \"this is my password\" -e infile outfile\n");
  
    return 0;
}

int main(int argc, char** argv)
{
   //./xcipher -p "this is my password" -e infile outfile

   int IsEncrypt = 0, option = -1, xcrypt = 0;
   char* pass;

   while ((option = getopt (argc, argv, "p:edh")) != -1)
   {
      switch(option)
      {
         case 'p':
                  pass = strdup(optarg);
                  break;
         case 'e':
                  if(xcrypt == 0)
                  {
                      IsEncrypt = 1;
                      xcrypt = 1;
                  }
                  else
                     return printHelp();
                  break;
         case 'd':
                  if(xcrypt == 0)
                  {
                      IsEncrypt = 0;
                      xcrypt = 1;
                  }
                   else
                     return printHelp();
                  break;

         case 'h':
                  return printHelp();
         case '?':
                if (optopt == 'p')
                    printf ("Option -p requires an argument.\n");
                 return printHelp();
         default:
                  return printHelp();

      }
   }

   if(argc-optind != 2)
   {
      return printHelp();
   }
   
   const char* inputFile = argv[optind];
   const char* outputFile = argv[optind+1];

   
   int passlength = strlen(pass);
   if(passlength < 6)
   {
       printf("User-level passwords should be at least 6 characters long");
       return 0;
   }
  
   // remove new lines in password
   printf("The passphrase length: %d\n", passlength);
   char passphrase[passlength+1];

  int i = 0, k = 0;
  for( i = 0; i < passlength; i++)
  {
     if(pass[i] != '\n')
     {
        passphrase[k] = pass[i];
        k++;
     }
     else
      printf(" removing a new line in pasword\n");
  }
  passphrase[k] = '\0';
  printf("PassPhrase: %s, %d\n", passphrase, strlen(passphrase));
  
  // calculate the MD5 digest of this passphrase
  unsigned char passwordDigest[17];
  memset(passwordDigest, 0, 17);
  printf("passphrase length: %d\n",  strlen(passphrase));
  MD5((const unsigned char *)passphrase,  strlen(passphrase), passwordDigest);
  passwordDigest[16] = '\0';

  // create the structure
  struct xcryptargs* userArgs = (struct xcryptargs*) malloc(sizeof(struct xcryptargs));
  memset(userArgs, 0, sizeof(struct xcryptargs));

  // set the password
  userArgs->keybuf = passwordDigest;

  // process the input file
  int len = strlen(inputFile) + 1;
  userArgs->infile = (char*)malloc(len);
  memset(userArgs->infile, 0, len);
  strcpy(userArgs->infile, inputFile);

  // process the output file
  len = strlen(outputFile) + 1;
  userArgs->outfile = (char*)malloc(len);
  memset(userArgs->outfile, 0, len);
  strcpy(userArgs->outfile, outputFile);

  // set the flag
  userArgs->flags = IsEncrypt;

  // set the length
  userArgs->keylen = strlen((char*) passwordDigest);

  // just print the user arguments
  printf(" Input File: %s with length %d\n", userArgs->infile, strlen(userArgs->infile));
  printf(" Output File: %s with length %d\n", userArgs->outfile, strlen(userArgs->outfile));
  printf(" Provided key: "); printDigest(userArgs->keybuf);
  printf(" Key length: %d\n", userArgs->keylen);
  printf(" Xcrypt Flag: %d\n", userArgs->flags);
   
  int rc = syscall(__NR_xcrypt,userArgs);
  if (rc == 0)
      printf("syscall returned %d and is successful\n", rc);
  else
      printf("syscall returned %d (errno=%d)\n", rc, errno);
 
  exit(rc);
}
