#include "main.h"


void login_or_register() {

    FILE* my_certificate = fopen("./trust_store/me.crt", "r");
    if (my_certificate == NULL) {

        char username[MAX_USERNAME_LEN+1];

        printf("Create username (max %d chars): ", MAX_USERNAME_LEN);
        fgets(username, MAX_USERNAME_LEN+1, stdin);
        username[strlen(username)-1] = '\0';

        generate_csr(username);

        char ca_ip[16];

        printf("Certificate Authority (CA): ");
        fgets(ca_ip, 16, stdin);
        ca_ip[strlen(ca_ip)-1] = '\0';

        get_cert(username, ca_ip);

    }
    fclose(my_certificate);

}


void* start_application(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    login_or_register();

    printf("[+] \n----\nApplication started\n----\n");

    while (1) {

        char username[MAX_USERNAME_LEN+1];
        char hostname[16];
        unsigned char session_key[SESSION_KEY_LEN];

        printf("Select user to chat: ");
        fgets(username, MAX_USERNAME_LEN+1, stdin);

        username[strlen(username)-1] = '\0';

        if (strcmp(username, "exit") == 0) {
            closesocket(socket_descriptor);
            break;
        }


        dns_lookup(username, hostname);

        struct sockaddr_in user_address;
        user_address.sin_family = AF_INET;
        user_address.sin_addr.s_addr = inet_addr(hostname);
        user_address.sin_port = htons(DEFAULT_USER_PORT);

        if (connect(socket_descriptor, (struct sockaddr*)&user_address, sizeof(user_address)) < 0) {
            printf("[-] failed to connect to the server [%s:%d]\n", inet_ntoa(user_address.sin_addr), ntohs(user_address.sin_port));
            continue;
        }

        char session_key_path[MAX_FILE_PATH] = "./trust_store/session_";
        strcat(session_key_path, username);
        strcat(session_key_path, ".txt");

        send_certificate(socket_descriptor, 1, MY_CERT_PATH);
        receive_certificate(socket_descriptor, 1, username, session_key);

        char cert_file_path[MAX_FILE_PATH] = "./cache_certs/";
        strcat(cert_file_path, username);
        strcat(cert_file_path, ".crt");

        if (verify_cert(cert_file_path) <= 0) {
            printf("[-] certificate verification failed\n");
            return NULL;
        }

        send_certificate(socket_descriptor, 3, session_key_path);

        char chat_file_path[MAX_FILE_PATH] = "./chats/";
        strcat(chat_file_path, username);
        strcat(chat_file_path, ".txt");




        int handshake_successful = 1;

        while (1) {

            FILE* open_chat_file = fopen(chat_file_path, "ab");

            if (handshake_successful) {
                char handshake_message[] = "\n[+] certificate handshake \n";

                fwrite(handshake_message, 1, strlen(handshake_message), open_chat_file);
                fprintf(open_chat_file, "[+] session key: ");
                for (int index = 0; index < SESSION_KEY_LEN; index++) {
                    fprintf(open_chat_file, "%.02x", session_key[index]);
                }
                fprintf(open_chat_file, "\n");

                handshake_successful = 0;
            }

            int packet_identifier = 2;
            printf(">>>");

            char message[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

            fgets(message, BUFFER_SIZE, stdin);

            int payload_size = strlen(message);

            if (strcmp(message, "exit\n") == 0) {
                closesocket(socket_descriptor);
                break;
            }

            fwrite("\t\t\t\t", 1, 4, open_chat_file);
            fwrite(message, 1, payload_size, open_chat_file);

            fclose(open_chat_file);

            memcpy(send_buffer, &packet_identifier, sizeof(packet_identifier));
            memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
            memcpy(send_buffer + 2*sizeof(packet_identifier), message, payload_size); //need to be changed payload_size to read_bytes

            send(socket_descriptor, send_buffer, payload_size + 2*sizeof(payload_size), 0);

        }
    }


    return NULL;
}


int main() {

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return -1;
    }

    const unsigned long long socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_descriptor == INVALID_SOCKET) {
        printf(" failed\n");
    }

    pthread_t application_thread;

    pthread_create(&application_thread, NULL, start_application, (void*)&socket_descriptor);

    pthread_join(application_thread, NULL);

    return 0;
}