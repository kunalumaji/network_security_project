#include "main.h"


void* receive_execute_send(void* arg) {

    const unsigned long long socket_descriptor = *(unsigned long long*)arg;

    int read_bytes, packet_identifier, payload_size;

    char receive_buffer[BUFFER_SIZE], send_buffer[BUFFER_SIZE];

    char username[MAX_USERNAME_LEN];

    int handshake_successful = 0;
    int session_key_exchanged = 0;
    while (1) {

        read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);

        if (read_bytes <= 0) {
            break;
        }
        memcpy(&packet_identifier, receive_buffer, sizeof(packet_identifier));
        memcpy(&payload_size, receive_buffer + sizeof(packet_identifier), sizeof(payload_size));


        if (packet_identifier == 1) {
            printf("[+] certificate received\n");

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

            handshake_successful = 1;
            //end lock here

            send_certificate(socket_descriptor, 1, MY_CERT_PATH);

        }
        else if (packet_identifier == 2) {
            printf("[+] message packet received\n");

            char chat_file_path[MAX_FILE_PATH] = "./chats/";
            strcat(chat_file_path, username);
            strcat(chat_file_path, ".txt");

            char session_key_path[MAX_FILE_PATH] = "./trust_store/session_";
            strcat(session_key_path, username);
            strcat(session_key_path, ".txt");

            size_t decrypted_session_key_len = 0;
            long long generated_on;

            unsigned char *plaintext;
            extract_decrypted_session_key(session_key_path, &generated_on, &plaintext);

            //apply lock here

            FILE* open_chat_file = fopen(chat_file_path, "ab");

            if (handshake_successful) {
                fprintf(open_chat_file, "\n----------\n[+] certificate handshake\n");
                handshake_successful = 0;
            }
            if (session_key_exchanged) {
                fprintf(open_chat_file, "[+] session key: ");
                for (int index = 0; index < decrypted_session_key_len; index++) {
                    fprintf(open_chat_file, "%.02x", plaintext[index]);
                }
                fprintf(open_chat_file, "\n----------\n");
                session_key_exchanged = 0;
            }

            //message_decryption
            unsigned char decrypted_message[BUFFER_SIZE + 16];
            int decrypted_message_len = 0;

            decrypt_message(receive_buffer + 2*sizeof(packet_identifier), read_bytes - 2*sizeof(packet_identifier), decrypted_message, &decrypted_message_len, plaintext);
            fwrite(decrypted_message, 1, decrypted_message_len, open_chat_file);
            fwrite("--", 1, 2, open_chat_file);

            fclose(open_chat_file);
        }
        else if (packet_identifier == 3) {
            printf("[+] session key received\n");

            char encrypted_session_key_path[MAX_FILE_PATH] = "./trust_store/enc_session_";
            strcat(encrypted_session_key_path, username);
            strcat(encrypted_session_key_path, ".txt");

            FILE* session_key_file = fopen(encrypted_session_key_path, "wb");

            fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), session_key_file);

            payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
            while (payload_size > 0) {
                read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
                fwrite(receive_buffer, 1, read_bytes, session_key_file);

                payload_size -= read_bytes;
            }

            fclose(session_key_file);

            size_t decrypted_session_key_len = 0;
            long long generated_on;

            unsigned char *plaintext;
            extract_encrypted_session_key(encrypted_session_key_path, &decrypted_session_key_len, &generated_on, &plaintext);

            char session_key_path[MAX_FILE_PATH] = "./trust_store/session_";
            strcat(encrypted_session_key_path, username);
            strcat(encrypted_session_key_path, ".txt");

            session_key_file = fopen(session_key_path, "wb");

            fwrite(plaintext, 1, decrypted_session_key_len, session_key_file);
            fprintf(session_key_file, "\n");
            fprintf(session_key_file, "%lld", generated_on);

            remove("./trust_store/enc_session_");

            session_key_exchanged = 1;
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
        printf("[-] client [%s]: failed to listen\n", inet_ntoa(server_address.sin_addr));
        return NULL;
    }

    printf("[+] client [%s:%d]: listening for request...\n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));

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