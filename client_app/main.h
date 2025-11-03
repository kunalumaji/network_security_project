#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <winsock2.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/pem.h>


#define ROOT_CERT_PATH "./trust_store/root.crt"
#define BUFFER_SIZE 1024
#define SECRET_KEY_PATH "./credentials/secret.pem"
#define CSR_FILE_PATH "./credentials/client.csr"
#define DEFAULT_CA_PORT 8888
#define DEFAULT_USER_PORT 8080
#define MAX_USERNAME_LEN 50
#define MAX_FILE_PATH 256

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


int verify_cert(char* input_cert);
int generate_csr(unsigned char* common_name);
int get_cert(unsigned char* common_name, char* ca_ip);
void extract_username(FILE* certificate_file, char* username);

int send_certificate(long long socket_descriptor, int packet_identifier);
int receive_certificate(long long socket_descriptor, int packet_identifier, char* username);

void* start_application(void* arg);