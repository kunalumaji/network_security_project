#include "main.h"


void* receive_execute_send(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    int read_bytes, packet_identifier, payload_size;

    char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

    while (1) {

        read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
        memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
        memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));

        char username[MAX_USERNAME_LEN];

        if (packet_identifier == 1) {
            // printf("[+] certificate received\n");

            //apply lock here

            FILE* temp_crt_file = fopen("./cache_certs/received.crt", "wb+");

            fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), temp_crt_file);

            payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
            while (payload_size > 0) {
                read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
                fwrite(receive_buffer, 1, read_bytes, temp_crt_file);

                payload_size -= read_bytes;
            }

            fseek(temp_crt_file, 0, SEEK_SET);
            extract_username(temp_crt_file, username);
            fclose(temp_crt_file);

            char crt_file_path[MAX_FILE_PATH] = "./cache_certs/";
            strcat(crt_file_path, username);
            strcat(crt_file_path, ".crt");

            remove(crt_file_path);
            rename("./cache_certs/received.crt", crt_file_path);

            //end lock here

            send_certificate(socket_descriptor, 1);
            // int ack_status = 1;
            //
            // memcpy(send_buffer, &ack_status, sizeof(ack_status));
            //
            // if (ack_status) {
            //
            //     FILE* my_cert = fopen("./trust_store/me.crt", "rb");
            //
            //     fseek(my_cert, 0, SEEK_END);
            //     payload_size = ftell(my_cert);
            //     fseek(my_cert, 0, SEEK_SET);
            //
            //     memcpy(send_buffer + sizeof(packet_identifier), &payload_size, sizeof(payload_size));
            //     read_bytes = fread(send_buffer + 2*sizeof(ack_status), 1, BUFFER_SIZE - 2*sizeof(ack_status), my_cert);
            //
            //     send(socket_descriptor, send_buffer, read_bytes + 2*sizeof(ack_status), 0);
            //
            //     while ((read_bytes = fread(send_buffer, 1, BUFFER_SIZE, my_cert)) > 0) {
            //
            //         send(socket_descriptor, send_buffer, read_bytes, 0);
            //     }
            //
            //     fclose(my_cert);
            //
            // }
            // else
            //     send(socket_descriptor, send_buffer, sizeof(ack_status), 0);

        }
        else if (packet_identifier == 2) {
            // printf("[+] message packet received\n");

            char chat_file_path[MAX_FILE_PATH] = "./chats/";
            strcat(chat_file_path, username);
            strcat(chat_file_path, ".txt");

            //apply lock here

            FILE* open_chat_file = fopen(chat_file_path, "ab");

            fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), open_chat_file);

            payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
            while (payload_size > 0) {
                read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
                fwrite(receive_buffer, 1, read_bytes, open_chat_file);

                payload_size -= read_bytes;
            }

            fclose(open_chat_file);
        }
        else {
            printf("[-] invalid request received\n");
            break;
        }
    }

    closesocket(socket_descriptor);

    return NULL;
}


void* listen_incoming_connections(void* arg) {

    long long socket_descriptor = *(long long*)arg;

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(DEFAULT_USER_PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    int address_length = sizeof(server_address);

    if (bind(socket_descriptor, (struct sockaddr*)&server_address, address_length) == SOCKET_ERROR) {
        printf("[-] socket binding failed\n");
        return NULL;
    }

    if (listen(socket_descriptor, 10) < 0) {
        printf("[-] CA [%s]: failed to listen\n", inet_ntoa(server_address.sin_addr));
        return NULL;
    }

    printf("[+] Client [%s:%d]: listening for request...\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

    while (1) {

        const unsigned long long accepting_socket = accept(socket_descriptor, (struct sockaddr*)&server_address, &address_length);

        if (accepting_socket == INVALID_SOCKET) {
            printf("[-] connection not accepted\n");
            continue;
        }

        printf("[+] connection accepted [%s]\n", inet_ntoa(server_address.sin_addr));

        pthread_t accepted_thread;
        pthread_create(&accepted_thread, NULL, receive_execute_send, (void*)&accepting_socket);
        pthread_detach(accepted_thread);

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

    pthread_t listening_thread;

    pthread_create(&listening_thread, NULL, listen_incoming_connections, (void*)&socket_descriptor);

    pthread_join(listening_thread, NULL);

    return 0;
}