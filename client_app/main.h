#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <winsock2.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


#define ROOT_CERT_PATH "./trust_store/root.crt"
#define MY_CERT_PATH "./trust_store/me.crt"

#define BUFFER_SIZE 1024
#define SECRET_KEY_PATH "./credentials/secret.pem"
#define CSR_FILE_PATH "./credentials/client.csr"
#define DEFAULT_CA_PORT 8888
#define DEFAULT_USER_PORT 8080
#define MAX_USERNAME_LEN 50
#define MAX_FILE_PATH 256

#define SESSION_KEY_LEN 16

#define SESSION_EXPIRY_TIME 10

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


int verify_cert(char* input_cert);
int generate_csr(unsigned char* common_name);
int get_cert(unsigned char* common_name, char* ca_ip);
void extract_username(FILE* certificate_file, char* username);

int send_certificate(long long socket_descriptor, int packet_identifier, char* cert_path);
int receive_certificate(long long socket_descriptor, int packet_identifier, char* username, unsigned char* session_key);

void* start_application(void* arg);

int dns_lookup(char* username, char* hostname);
int add_user(char* username, char* hostname);
int validate_expiry(long long input_time, long long validity);


int encrypt_message(char* message, int message_len, unsigned char* encrypted_message, int* encrypted_message_len, unsigned char* session_key);
int decrypt_message(char* encrypted_message, int encrypted_message_len, unsigned char* decrypted_message, int* decrypted_message_len, unsigned char* session_key);

void extract_encrypted_session_key(char session_key_path[256], size_t* decrypted_session_key_len, long long* generated_on, unsigned char **plaintext);
void extract_decrypted_session_key(char session_key_path[MAX_FILE_PATH], long long* generated_on, unsigned char **plaintext);
void create_session_key(unsigned char *session_key, X509 *cert, char session_key_path[MAX_FILE_PATH], char decrypted_session_key_path[MAX_FILE_PATH]);