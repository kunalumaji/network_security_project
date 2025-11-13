#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <winsock2.h>
#include <pthread.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <dirent.h>


#define BUFFER_SIZE 1024
#define MAX_USERNAME_LEN 50
#define MAX_FILE_PATH 256
#define CA_SECRET_KEY "./credentials/secret.pem"
#define CA_CERT_PATH "./credentials/ca.crt"

#define SECRET_KEY_PATH "./credentials/secret.pem"
#define CSR_FILE_PATH "./credentials/client.csr"

#define DEFAULT_CA_PORT 8888

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


long generate_next_serial_number(void) {

    unsigned char serial_number[sizeof(long)];
    long long_serial_number;

    RAND_bytes(serial_number, sizeof(serial_number));
    memcpy(&long_serial_number, serial_number, sizeof(serial_number));

    return abs(long_serial_number);

}


int verify_cert(char* input_cert) {

    FILE* cert_chain_file = fopen(input_cert, "r");

    X509* client_cert = PEM_read_X509(cert_chain_file, NULL, NULL, NULL);

    STACK_OF(X509) *chain = sk_X509_new_null();

    X509* cert = NULL;

    while ((cert = PEM_read_X509(cert_chain_file, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }

    fclose(cert_chain_file);

    FILE* root_cert_file = fopen("./root/root.crt", "r");

    X509* root_cert = PEM_read_X509(root_cert_file, NULL, NULL, NULL);

    fclose(root_cert_file);

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, root_cert);

    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, store, client_cert, chain);

    int verification_status = X509_verify_cert(store_ctx);

    if (verification_status == 1) {
        return 1;
    }

    return 0;

}


int issue_cert(char* ca_private_key, char* ca_cert, char* client_csr, char* client_cert, int is_ca, long serial_number_generated) {

    FILE *cakey_file = fopen(ca_private_key, "r");
    EVP_PKEY *ca_pkey = PEM_read_PrivateKey(cakey_file, NULL, NULL, NULL);
    fclose(cakey_file);

    FILE *cacert_file = fopen(ca_cert, "r");
    X509 *ca_cert_info = PEM_read_X509(cacert_file, NULL, NULL, NULL);

    FILE *csr_file = fopen(client_csr, "r");
    X509_REQ *req = PEM_read_X509_REQ(csr_file, NULL, NULL, NULL);
    fclose(csr_file);

    X509 *cert = X509_new();

    X509_set_version(cert, 2);

    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial_number_generated);

    // printf("%s\n", generated_file_path);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60*60*24*365);

    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));

    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert_info));

    EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    if (is_ca) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");

        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }


    if (!X509_sign(cert, ca_pkey, EVP_sha256())) {
        return 0;
    }

    FILE *out = fopen(client_cert, "w");
    PEM_write_X509(out, cert);

    X509* next_cert = NULL;

    fseek(cacert_file, 0, SEEK_SET);
    while ((next_cert = PEM_read_X509(cacert_file, NULL, NULL, NULL)) != NULL) {
        PEM_write_X509(out, next_cert);
    }

    fclose(cacert_file);
    fclose(out);


    EVP_PKEY_free(ca_pkey);
    X509_free(ca_cert_info);
    X509_free(cert);
    X509_REQ_free(req);
    X509_free(next_cert);

    return 1;
}

struct socket_context {
    unsigned long long socket_descriptor;
    struct sockaddr_in* server_address;
    int* addrlen;
};


void* receive_execute_send(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    int read_bytes, packet_identifier, payload_size;

    char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

    read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
    memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
    memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));

    if (packet_identifier == 1 || packet_identifier == 2) {
        printf("[+] request for 'issue certificate'\n");

        FILE* temp_csr_file = fopen("./temp_csr_file.csr", "wb");

        fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), temp_csr_file);

        payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
        while (payload_size > 0) {
            read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
            printf("%d bytes read from csr\n", read_bytes);
            fwrite(receive_buffer, 1, read_bytes, temp_csr_file);

            payload_size -= read_bytes;
        }

        fclose(temp_csr_file);


        long serial_number_generated = generate_next_serial_number();
        char generated_file_path[100] = "./issued_certs/";
        ltoa(serial_number_generated, generated_file_path + strlen(generated_file_path), 10);
        strcat(generated_file_path, ".crt");
        int ack_status = issue_cert(CA_SECRET_KEY, CA_CERT_PATH, "./temp_csr_file.csr", generated_file_path, packet_identifier == 1 ? 0 : 1, serial_number_generated);

        remove("./temp_csr_file.csr");

        memcpy(send_buffer, &ack_status, sizeof(ack_status));

        if (ack_status) {

            FILE* temp_crt_file = fopen(generated_file_path, "rb");

            fseek(temp_crt_file, 0, SEEK_END);
            int payload_size = ftell(temp_crt_file);
            fseek(temp_crt_file, 0, SEEK_SET);

            memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
            read_bytes = fread(send_buffer + 2*sizeof(ack_status), 1, BUFFER_SIZE - 2*sizeof(ack_status), temp_crt_file);


            send(socket_descriptor, send_buffer, read_bytes + 2*sizeof(ack_status), 0);

            while ((read_bytes = fread(send_buffer, 1, BUFFER_SIZE, temp_crt_file)) > 0) {

                send(socket_descriptor, send_buffer, read_bytes, 0);
            }

            fclose(temp_crt_file);

        }
        else
            send(socket_descriptor, send_buffer, sizeof(ack_status), 0);

    }
    else if (packet_identifier == 2) {
        printf("[+] request for 're-issue certificate'\n");

        int ack_status = 2;
        memcpy(send_buffer, &ack_status, sizeof(int));
        send(socket_descriptor, send_buffer, sizeof(int), 0);
    }
    else {
        printf("[-] invalid request received\n");
    }

    closesocket(socket_descriptor);

    return NULL;

}


void* listen_connections(void* arg) {

    struct socket_context* context = (struct socket_context*)arg;

    if (listen(context->socket_descriptor, 10) < 0) {
        printf("[-] CA [%s]: failed to listen\n", inet_ntoa(context->server_address->sin_addr));
        return NULL;
    }

    printf("[+] CA [%s:%d]: listening for request...\n", inet_ntoa(context->server_address->sin_addr), context->server_address->sin_port);

    while (true) {

        const unsigned long long accepting_socket = accept(context->socket_descriptor, (struct sockaddr*)context->server_address, context->addrlen);

        if (accepting_socket == INVALID_SOCKET) {
            printf("[-] connection not accepted\n");
            continue;
        }

        printf("[+] connection accepted [%s]\n", inet_ntoa(context->server_address->sin_addr));

        pthread_t accepted_thread;
        pthread_create(&accepted_thread, NULL, receive_execute_send, (void*)&accepting_socket);
        pthread_detach(accepted_thread);

    }

    return NULL;
}


void* application(void* arg) {

    printf("[+] application started\n");

    return NULL;
}


void print_username_from_cert(const char *path) {
    FILE *certificate = fopen(path, "r");

    X509 *cert = PEM_read_X509(certificate, NULL, NULL, NULL);
    fclose(certificate);

    if (!cert) {
        printf("[-] Failed to read certificate: %s\n", path);
        return;
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    char username[50+1];

    int len = X509_NAME_get_text_by_NID(subject, NID_commonName, username, sizeof(username));
    if (len > 0)
        printf("[+]-> %s\n", username);
    else
        printf("[-] %s -> Client\n", path);

    X509_free(cert);
}



int generate_csr(unsigned char* common_name) {

    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bne, NULL);

    EVP_PKEY *key_holder = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key_holder, rsa);

    X509_REQ *cs_request = X509_REQ_new();
    X509_REQ_set_version(cs_request, 1);

    X509_NAME *name_block = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name_block, "CN", MBSTRING_ASC, common_name, -1,-1,0);
    X509_REQ_set_subject_name(cs_request, name_block);
    X509_REQ_set_pubkey(cs_request, key_holder);

    if (!X509_REQ_sign(cs_request,key_holder, EVP_sha256())) {
        printf("[-] failed to create certificate request\n");
        return 0;
    }

    FILE* private_key_file = fopen(SECRET_KEY_PATH, "wb");
    PEM_write_PrivateKey(private_key_file, key_holder, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    FILE* cs_request_file = fopen(CSR_FILE_PATH, "wb");
    PEM_write_X509_REQ(cs_request_file, cs_request);
    fclose(cs_request_file);

    printf("[+] certificate request file created\n");

    return 1;

}


int get_cert(unsigned char* common_name, char* ca_ip) {

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }

    const unsigned long long socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(ca_ip);
    server_address.sin_port = htons(DEFAULT_CA_PORT);

    if (connect(socket_descriptor, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        printf("[-] CA is unreachable [%s]\n", inet_ntoa(server_address.sin_addr));
        return 0;
    }

    char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];


    if (generate_csr(common_name) <= 0) {
        return 0;
    }

    FILE* csr_file = fopen(CSR_FILE_PATH, "rb");

    fseek(csr_file, 0, SEEK_END);
    int payload_size = ftell(csr_file);
    fseek(csr_file, 0, SEEK_SET);

    char csr_buffer[BUFFER_SIZE];

    int packet_identifier = 2;

    int read_bytes = fread(csr_buffer, 1, BUFFER_SIZE - 2*sizeof(packet_identifier), csr_file);

    memcpy(send_buffer, &packet_identifier, sizeof(packet_identifier));
    memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
    memcpy(send_buffer + 2*sizeof(packet_identifier), csr_buffer, read_bytes);

    send(socket_descriptor, send_buffer, read_bytes + 2*sizeof(packet_identifier), 0);

    while ((read_bytes = fread(send_buffer, 1, BUFFER_SIZE, csr_file)) > 0) {
        send(socket_descriptor, send_buffer, read_bytes, 0);
    }

    read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
    memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
    memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));

    if (packet_identifier == 0) {
        printf("[-] certificate request declined by CA\n");
        return 0;
    }

    FILE* certificate = fopen("./credentials/ca.crt", "wb");

    fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), certificate);

    payload_size -= read_bytes - 2*sizeof(packet_identifier);
    while ((payload_size) > 0) {
        read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);

        fwrite(receive_buffer, 1, read_bytes, certificate);
        payload_size -= read_bytes;
    }

    fclose(certificate);

    printf("[+] certificate issued by the CA\n");

    return 1;

}
double get_time_difference(struct timespec start, struct timespec end) {
    double start_ms = (double)start.tv_sec * 1000.0 + (double)start.tv_nsec / 1000000.0;
    double end_ms   = (double)end.tv_sec   * 1000.0 + (double)end.tv_nsec   / 1000000.0;
    return end_ms - start_ms;
}

void login_or_register() {

    FILE* my_certificate = fopen("./credentials/ca.crt", "r");
    if (my_certificate == NULL) {

        char username[MAX_USERNAME_LEN+1];

        printf("Create CA name (max %d chars): ", MAX_USERNAME_LEN);
        fgets(username, MAX_USERNAME_LEN+1, stdin);
        username[strlen(username)-1] = '\0';

        generate_csr(username);

        char ca_ip[16];

        printf("Certificate Authority (CA): ");
        fgets(ca_ip, 16, stdin);
        ca_ip[strlen(ca_ip)-1] = '\0';

        struct timespec ca_registration_start_time, ca_registration_end_time;

        clock_gettime(CLOCK_MONOTONIC, &ca_registration_start_time);
        get_cert(username, ca_ip);
        clock_gettime(CLOCK_MONOTONIC, &ca_registration_end_time);

        printf("-\nTIme for CA Registration: %f\n-\n", get_time_difference(ca_registration_start_time, ca_registration_end_time));
    }
    fclose(my_certificate);

}



int main(int args, char **argv) {

    char* command = argv[1];

    login_or_register();

    if (strcmp("list-clients", command) == 0) {

        const char *dir_path = "./issued_certs";

        DIR* directory = opendir(dir_path);

        struct dirent *entry;
        int total_issued_certs = 0;

        printf("\nListing issued certificates\n\n");
        while ((entry = readdir(directory)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;

            const char *ext = strrchr(entry->d_name, '.');
            if (!ext || strcmp(ext, ".crt") != 0)
                continue;

            char fullpath[MAX_FILE_PATH];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, entry->d_name);

            print_username_from_cert(fullpath);
            total_issued_certs++;
        }

        closedir(directory);

        printf("---\nTotal issued certs: %d\n", total_issued_certs);

    }
    else if (strcmp("start-server", command) == 0) {

        WSADATA wsaData;

        if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
            printf("WSAStartup failed\n");
            return -1;
        }

        const unsigned long long socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

        if (socket_descriptor == INVALID_SOCKET) {
            printf("socket creation failed\n");
        }

        struct sockaddr_in server_address;
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(8888);
        server_address.sin_addr.s_addr = INADDR_ANY;

        int address_length = sizeof(server_address);

        if (bind(socket_descriptor, (struct sockaddr*)&server_address, address_length) == SOCKET_ERROR) {
            printf("[-] socket binding failed\n");
        }

        printf("[+] socket bind successful\n");

        struct socket_context* context = (struct socket_context*)malloc(sizeof(struct socket_context));
        context->socket_descriptor = socket_descriptor;
        context->server_address = &server_address;
        context->addrlen = &address_length;

        pthread_t listening_thread_id;
        pthread_create(&listening_thread_id, NULL, listen_connections, (void*)context);

        pthread_join(listening_thread_id, NULL);

        closesocket(socket_descriptor);
    }

    return 0;
}

