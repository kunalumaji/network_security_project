#include "main.h"


int verify_cert(char* input_cert) {

    FILE* cert_chain_file = fopen(input_cert, "r");

    X509* client_cert = PEM_read_X509(cert_chain_file, NULL, NULL, NULL);

    STACK_OF(X509) *chain = sk_X509_new_null();

    X509* cert = NULL;

    while ((cert = PEM_read_X509(cert_chain_file, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }

    fclose(cert_chain_file);

    FILE* root_cert_file = fopen(ROOT_CERT_PATH, "r");

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

    int packet_identifier = 1;

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

    FILE* certificate = fopen("./trust_store/me.crt", "wb");

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


struct socket_context {
    long long socket_descriptor;
    struct sockaddr_in* server_address;
    int *addrlen;
};


void extract_username(FILE* certificate_file, char* username) {

    printf("Extracting username\n");

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);

    X509_NAME* subject = X509_get_subject_name(certificate);
    X509_NAME_get_text_by_NID(subject, NID_commonName, username, MAX_USERNAME_LEN);

    X509_free(certificate);
}

int send_certificate(long long socket_descriptor, int packet_identifier) {

    int read_bytes = 0;
    char send_buffer[BUFFER_SIZE];

    memcpy(send_buffer, &packet_identifier, sizeof(packet_identifier));

    if (packet_identifier) {

        FILE* my_cert = fopen("./trust_store/me.crt", "rb");

        fseek(my_cert, 0, SEEK_END);
        int payload_size = ftell(my_cert);
        fseek(my_cert, 0, SEEK_SET);

        memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
        read_bytes = fread(send_buffer + 2*sizeof(packet_identifier), 1, BUFFER_SIZE - 2*sizeof(packet_identifier), my_cert);

        send(socket_descriptor, send_buffer, read_bytes + 2*sizeof(packet_identifier), 0);

        while ((read_bytes = fread(send_buffer, 1, BUFFER_SIZE, my_cert)) > 0) {

            send(socket_descriptor, send_buffer, read_bytes, 0);
        }

        fclose(my_cert);

    }

    return 1;
}


int receive_certificate(long long socket_descriptor, int packet_identifier, char* username) {

    int read_bytes = 0;
    int payload_size;
    char receive_buffer[BUFFER_SIZE];

    read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
    memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
    memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));

    //apply lock here

    char crt_file_path[MAX_FILE_PATH] = "./cache_certs/";
    strcat(crt_file_path, username);
    strcat(crt_file_path, ".crt");

    printf("crt_file_path: %s\n", crt_file_path);

    FILE* temp_crt_file = fopen(crt_file_path, "wb");

    fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), temp_crt_file);

    payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
    while (payload_size > 0) {
        read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
        fwrite(receive_buffer, 1, read_bytes, temp_crt_file);

        payload_size -= read_bytes;
    }

    fclose(temp_crt_file);

    char certificate_username[MAX_USERNAME_LEN];

    extract_username(temp_crt_file, certificate_username);

    if (strcmp(certificate_username, username) == 0) {
        return 1;
    }
    //end lock here

    return 0;
}


// void* start_application(void* arg) {
//
//     const unsigned long long socket_descriptor = *(unsigned long long*)arg;
//
//     printf("[+] \n----\nApplication started\n----\n");
//
//     while (1) {
//
//         char username[MAX_USERNAME_LEN+1];
//         printf("Select user to chat: ");
//         fgets(username, MAX_USERNAME_LEN+1, stdin);
//
//         username[strlen(username)-1] = '\0';
//
//         if (strcmp(username, "exit") == 0) {
//             closesocket(socket_descriptor);
//             break;
//         }
//
//         struct sockaddr_in user_address;
//         user_address.sin_family = AF_INET;
//         user_address.sin_addr.s_addr = inet_addr(username);
//         user_address.sin_port = htons(9999);
//
//         if (connect(socket_descriptor, (struct sockaddr*)&user_address, sizeof(user_address)) < 0) {
//             printf("[-] failed to connect to the server\n");
//             continue;
//         }
//
//         send_certificate(socket_descriptor, 1);
//         int receive_status = receive_certificate(socket_descriptor, 1, username);
//
//         char chat_file_path[MAX_FILE_PATH] = "./chats/";
//         strcat(chat_file_path, username);
//         strcat(chat_file_path, ".txt");
//
//         char cert_file_path[MAX_FILE_PATH] = "./cache_certs/";
//         strcat(cert_file_path, username);
//         strcat(cert_file_path, ".crt");
//
//         if (verify_cert(cert_file_path) <= 0) {
//             printf("[-] certificate verification failed\n");
//             return NULL;
//         }
//
//         printf("%s\n", chat_file_path);
//
//         while (1) {
//
//             FILE* open_chat_file = fopen(chat_file_path, "ab");
//
//             int packet_identifier = 2;
//             printf(">>>");
//
//             char message[BUFFER_SIZE], send_buffer[BUFFER_SIZE];
//
//             fgets(message, BUFFER_SIZE, stdin);
//
//             int payload_size = strlen(message)-1;
//
//             if (strcmp(message, "exit") == 0) {
//                 closesocket(socket_descriptor);
//                 break;
//             }
//
//             fwrite("\t\t", 1, 2, open_chat_file);
//             fwrite(message, 1, payload_size, open_chat_file);
//
//             fclose(open_chat_file);
//
//             memcpy(send_buffer, &packet_identifier, sizeof(packet_identifier));
//             memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
//             memcpy(send_buffer + 2*sizeof(packet_identifier), message, payload_size); //need to be changed payload_size to read_bytes
//
//             send(socket_descriptor, send_buffer, payload_size + 2*sizeof(payload_size), 0);
//
//         }
//     }
//
//
//     return NULL;
// }


// void* receive_execute_send(void* arg) {
//
//     const unsigned long long socket_descriptor = *(unsigned long long*)arg;
//
//     int read_bytes, packet_identifier, payload_size;
//
//     char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];
//
//     read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
//     memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
//     memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));
//
//     if (packet_identifier == 1) {
//         printf("[+] certificate received\n");
//
//         FILE* temp_crt_file = fopen("./cache_certs/received.crt", "wb");
//
//         fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), temp_crt_file);
//
//         payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
//         while (payload_size > 0) {
//             read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
//             fwrite(receive_buffer, 1, read_bytes, temp_crt_file);
//
//             payload_size -= read_bytes;
//         }
//
//         fclose(temp_crt_file);
//
//
//         int ack_status = 1;
//
//         memcpy(send_buffer, &ack_status, sizeof(ack_status));
//
//         if (ack_status) {
//
//             FILE* my_cert = fopen("./trust_store/me.crt", "rb");
//
//             fseek(my_cert, 0, SEEK_END);
//             int payload_size = ftell(my_cert);
//             fseek(my_cert, 0, SEEK_SET);
//
//             memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
//             read_bytes = fread(send_buffer + 2*sizeof(ack_status), 1, BUFFER_SIZE - 2*sizeof(ack_status), my_cert);
//
//             send(socket_descriptor, send_buffer, read_bytes + 2*sizeof(ack_status), 0);
//
//             while ((read_bytes = fread(send_buffer, 1, BUFFER_SIZE, my_cert)) > 0) {
//
//                 send(socket_descriptor, send_buffer, read_bytes, 0);
//             }
//
//             fclose(my_cert);
//
//         }
//         else
//             send(socket_descriptor, send_buffer, sizeof(ack_status), 0);
//
//     }
//     else if (packet_identifier == 2) {
//         printf("[+] reserved packet for some other functionality\n");
//
//         int ack_status = 2;
//         memcpy(send_buffer, &ack_status, sizeof(int));
//         send(socket_descriptor, send_buffer, sizeof(int), 0);
//     }
//     else {
//         printf("[-] invalid request received\n");
//     }
//
//     closesocket(socket_descriptor);
//
//     return NULL;
// }


// void* listen_incoming_connections(void* arg) {
//
//     long long socket_descriptor = *(long long*)arg;
//
//     struct sockaddr_in server_address;
//     server_address.sin_family = AF_INET;
//     server_address.sin_port = htons(DEFAULT_USER_PORT);
//     server_address.sin_addr.s_addr = INADDR_ANY;
//
//     int address_length = sizeof(server_address);
//
//     if (bind(socket_descriptor, (struct sockaddr*)&server_address, address_length) == SOCKET_ERROR) {
//         printf("[-] socket binding failed\n");
//     }
//
//     if (listen(socket_descriptor, 10) < 0) {
//         printf("[-] CA [%s]: failed to listen\n", inet_ntoa(server_address.sin_addr));
//         return NULL;
//     }
//
//     printf("[+] Client [%s:%d]: listening for request...\n", inet_ntoa(server_address.sin_addr), server_address.sin_port);
//
//     while (1) {
//
//         const unsigned long long accepting_socket = accept(socket_descriptor, (struct sockaddr*)&server_address, &address_length);
//
//         if (accepting_socket == INVALID_SOCKET) {
//             printf("[-] connection not accepted\n");
//             continue;
//         }
//
//         printf("[+] connection accepted [%s]\n", inet_ntoa(server_address.sin_addr));
//
//         pthread_t accepted_thread;
//         pthread_create(&accepted_thread, NULL, receive_execute_send, (void*)&accepting_socket);
//         pthread_detach(accepted_thread);
//
//     }
//
//     return NULL;
// }


void* listen_incoming_connections(void* arg);

int main() {

    // generate_csr("kunalumaji");

    // get_cert("kunalumaji", "127.0.0.1");
    //
    // if (verify_cert("./trust_store/me.crt")) {
    //     printf("verified certificate\n");
    // }
    // else
    //     printf("invalid certificate");

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }

    const unsigned long long socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_descriptor == INVALID_SOCKET) {
        printf(" failed\n");
    }

    pthread_t listening_thread, application_thread;

    pthread_create(&listening_thread, NULL, listen_incoming_connections, (void*)&socket_descriptor);
    pthread_create(&application_thread, NULL, start_application, (void*)&socket_descriptor);

    pthread_join(listening_thread, NULL);
    pthread_join(application_thread, NULL);

    return 0;
}