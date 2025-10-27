#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <winsock2.h>
#include <pthread.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>


#define BUFFER_SIZE 1024
#define CA_SECRET_KEY "./credentials/secret.pem"
#define CA_CERT_PATH "./credentials/ca.crt"

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


void log_to_file(const char* format, ...) {

}


void* receive_execute_send(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    int read_bytes, packet_identifier, payload_size;

    char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

    read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
    memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
    memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));

    if (packet_identifier == 1) {
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

        int ack_status = issue_cert(CA_SECRET_KEY, CA_CERT_PATH, "./temp_csr_file.csr", generated_file_path, 0, serial_number_generated);

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


int main() {

    char* verifying_path = "./client_app/trust_store/me.crt";

    if (verify_cert(verifying_path)) {
        printf("Verified certificate ...\n");
    }
    else
        printf("Invalid certificate\n");

    // char* ca_private_key = "./root/in/in.pem";
    // char* ca_cert = "./root/in/in.crt";
    // char* client_csr = "./root/in/mh/mh.csr";
    // char* client_cert = "./root/in/mh/mh.crt";
    //
    // if (issue_cert(ca_private_key, ca_cert, client_csr, client_cert, 0)) {
    //     printf("Isssued certificate ...\n");
    // }

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }

    const unsigned long long socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_descriptor == INVALID_SOCKET) {
        printf(" failed\n");
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

    // Listen and Application threads
    pthread_t listening_thread_id;
    pthread_create(&listening_thread_id, NULL, listen_connections, (void*)context);

    pthread_t application_thread_id;
    pthread_create(&application_thread_id, NULL, application, NULL);

    pthread_join(listening_thread_id, NULL);
    pthread_join(application_thread_id, NULL);

    closesocket(socket_descriptor);

    return 0;
}

