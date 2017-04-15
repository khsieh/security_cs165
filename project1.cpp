#include <iostream>
#include <openssl/md5.h>
#include <string>
#include <locale>
#include <cstdlib>
#include <pthread.h>
#include <ctime>

#include "base64.h"

#define NUM_THREADS 10
#define ROUNDS 1000
bool solved = false;
static int num_active_threads = 0;

using namespace std;

struct thread_data {
  string pass;
  string shadow;
  string salt;
};

// Increments char in string at pos by 1. eg 'a' -> 'b'
string replaceChar(string input, int pos) {
  string modChar = "";
  modChar.push_back(input.at(pos));
  modChar.at(0)++;
  input.replace(pos, 1, modChar);
  return input;
}

// Increments the char after a 'z' and resets the chars before to 'a'
// Ex: 'zzza' -> 'aaab'
string updateLast (string input, int pos) {
  string modChar = "";
  modChar.push_back(input.at(pos));
  modChar.at(0)++;
  input.replace(pos, 1, modChar);
  for (int i = 0; i < pos; i++) {
    input.replace(i, 1, "a");
  }
  return input;
}

// Takes in an input and increments the appropriate char
string passGenerator(string input) {
  int i = 0;
  for (int i = 0; i < input.size(); i++) {
    if (input.at(i) != 'z') {
      return replaceChar(input, i);
    }
    else {
      while (input.at(i) == 'z' && i < input.size() - 1) {
        i++;
        if (input.at(i) != 'z') {
          //~ cout << "Updating last!" << endl;
          return updateLast(input, i);
        }
      }

      string newInput = "";
      for (int i = 0; i < input.size() + 1; i++) {
        newInput.push_back('a');
      }
      return newInput;
    }
  }

  return input;
}

// Called by threads. Takes in a pass, shadow, and salt, and performs the
// md5base64 crypt algorithm.
void *HashAndCompare(void *threadarg){

  struct thread_data *my_data;
  my_data = (struct thread_data *) threadarg;

  string shadowPass(my_data->shadow.c_str());
  unsigned char final_digest[16];
  const char* pass = my_data->pass.c_str();
  const char* salt = my_data->salt.c_str();

  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, pass, strlen(pass));
  MD5_Update(&c, salt, strlen(salt));
  MD5_Update(&c, pass, strlen(pass));

  MD5_CTX c1;
  MD5_Init(&c1);

  //WEIRD STUFF, Intermediate setup
  char digest[MD5_DIGEST_LENGTH];

  //get digest
  MD5((unsigned char*)pass, MD5_DIGEST_LENGTH, (unsigned char*) digest);

  MD5_Update(&c1,digest,MD5_DIGEST_LENGTH);

  MD5_Update(&c1, pass, strlen(pass));
  MD5_Update(&c1, salt, strlen(salt));
  MD5_Update(&c1, pass, strlen(pass));

  char intermediate[MD5_DIGEST_LENGTH];
  strncpy(intermediate,digest,MD5_DIGEST_LENGTH);

  int temp_keylen = strlen(pass);
  while(temp_keylen > 0){
    MD5_Update(&c,intermediate,temp_keylen > 16 ? 16 : temp_keylen);
    temp_keylen -= 16;
  }
  temp_keylen = strlen(pass);

  while (temp_keylen > 0) {
    if(temp_keylen & 1 == 1){
      MD5_Update(&c,&intermediate[0],1);
    }
    else{
      MD5_Update(&c,&pass[0],1);
    }
    temp_keylen >>=1;
  }

  temp_keylen = strlen(pass);

  const int block_size = 16;
  // start x1000 iterations
  for (int i = 0; i < ROUNDS; i++) {
    if (i % 2 == 0) {   // Even
      // update Intermediate
      MD5_Update(&c1,intermediate,block_size);
    }
    else {              // Odd
      // update password
      MD5_Update(&c1,pass,temp_keylen);
    }

    if (i % 3 != 0) {   // Divisible by 3
      // update salt
      MD5_Update(&c1,salt,strlen(salt));
    }
    if (i % 7 != 0) {   // Divisible by 7
      // password
      MD5_Update(&c1,pass,temp_keylen);
    }

    if (i % 2 == 0) {   // Even
      // Intermediate
      MD5_Update(&c1,intermediate,block_size);
    }
    else {              // Odd
      // password
      MD5_Update(&c1,pass,temp_keylen);
    }
  }

  char result[33];
  MD5_Final((unsigned char*)&final_digest, &c1);
  // string resString(result,strlen(result));
  string encoded = base64_encode(reinterpret_cast<const unsigned char*>(final_digest), MD5_DIGEST_LENGTH);
  cout << "Encoded: " << encoded << endl;
  char readable[33];
    for (int i = 0; i < 16; i++)
        sprintf(&readable[i*2], "%02x", (unsigned int)final_digest[i]);

  string finalResult = base64_encode(reinterpret_cast<const unsigned char*>(readable),33);

  if (readable == shadowPass) {
    cout <<"CRACKED!?" << endl;
    solved = true;
  }
  else {
    // cout << "FAIL" << endl;
  }
  num_active_threads--;
  pthread_exit(NULL);
}

//testing password generator
void testPassGen() {
  string a = "a";
  for (int i = 0; i < 1000000; i++) {
    cout << a << endl;
    a = passGenerator(a);
  }
}

int main() {

  string a = "a";
  string salt = "hfT7jp2q"; //actual salt
  // string salt = "xyz"; //test salt
  string b = "";

  unsigned char shadow[23] = "eZhkYfvJ3wbqT1h/iIJLq/";
  // unsigned char shadow[23] = "OcPwHHMV7Y2fEaYljaqOX/"; //test shadow
  string base64_normal = base64_encode(reinterpret_cast<const unsigned char*>(shadow),23);
  string shadowStr = "eZhkYfvJ3wbqT1h/iIJLq/"; //actual shadow
  // string shadowStr = "OcPwHHMV7Y2fEaYljaqOX/"; // test shadow

  // HashAndCompare(&td);
  pthread_t threads[NUM_THREADS];
  struct thread_data td[NUM_THREADS];
  pthread_attr_t attr;
  void *status;
  int rc;
  int i = 0, j = 0;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  while (!solved) {
    for( i = 0; i < NUM_THREADS; i++ ) {
      b = a;
      a = passGenerator(a);

      td[i].pass = b;
      td[i].shadow = shadowStr;
      td[i].salt = salt;

      rc = pthread_create(&threads[i], NULL, HashAndCompare, (void *)&td[i]);
      if (rc){
        cerr << "Error:unable to create thread," << rc << endl;
        exit(-1);
      }
      num_active_threads++;
    }

    // free attribute and wait for the other threads
   pthread_attr_destroy(&attr);
   for( i = 0; i < NUM_THREADS; i++ ){
      rc = pthread_join(threads[i], &status);
      if (rc){
         cout << "Error:unable to join," << rc << endl;
         exit(-1);
      }
    }
  }

  cout << "pass: " << b << endl;

  return 0;
}
