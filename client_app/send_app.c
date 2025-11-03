#include "main.h"

void* start_application(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    printf("[+] \n----\nApplication started\n----\n");

    while (1) {

        char username[MAX_USERNAME_LEN+1];
        printf("Select user to chat: ");
        fgets(username, MAX_USERNAME_LEN+1, stdin);

        username[strlen(username)-1] = '\0';

        if (strcmp(username, "exit") == 0) {
            closesocket(socket_descriptor);
            break;
        }

        struct sockaddr_in user_address;
        user_address.sin_family = AF_INET;
        user_address.sin_addr.s_addr = inet_addr(username);
        user_address.sin_port = htons(9999);

        if (connect(socket_descriptor, (struct sockaddr*)&user_address, sizeof(user_address)) < 0) {
            printf("[-] failed to connect to the server\n");
            continue;
        }

        send_certificate(socket_descriptor, 1);
        receive_certificate(socket_descriptor, 1, username);

        char chat_file_path[MAX_FILE_PATH] = "./chats/";
        strcat(chat_file_path, username);
        strcat(chat_file_path, ".txt");

        char cert_file_path[MAX_FILE_PATH] = "./cache_certs/";
        strcat(cert_file_path, username);
        strcat(cert_file_path, ".crt");


        if (verify_cert(cert_file_path) <= 0) {
            printf("[-] certificate verification failed\n");
            return NULL;
        }

        printf("%s\n", chat_file_path);

        while (1) {

            FILE* open_chat_file = fopen(chat_file_path, "ab");

            int packet_identifier = 2;
            printf(">>>");

            char message[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

            fgets(message, BUFFER_SIZE, stdin);

            int payload_size = strlen(message)-1;

            if (strcmp(message, "exit") == 0) {
                closesocket(socket_descriptor);
                break;
            }

            fwrite("\t\t", 1, 2, open_chat_file);
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