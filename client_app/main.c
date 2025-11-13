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

int add_user(char* username, char* hostname) {
    FILE *contacts = fopen("./contacts.txt", "ab");
    if (contacts == NULL) {
        printf("[-] failed to open contact file\n");
        return 0;
    }

    fprintf(contacts, "\n%s %s", username, hostname);
    fclose(contacts);

    return 1;
}

double get_time_difference(struct timespec start, struct timespec end) {
    double start_ms = (double)start.tv_sec * 1000.0 + (double)start.tv_nsec / 1000000.0;
    double end_ms   = (double)end.tv_sec   * 1000.0 + (double)end.tv_nsec   / 1000000.0;
    return end_ms - start_ms;
}


int dns_lookup(char *username, char *hostname) {
    FILE *fp = fopen("./contacts.txt", "r");

    char line[MAX_USERNAME_LEN + 16 + 1];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';

        char file_user[MAX_USERNAME_LEN], file_ip[15];
        if (sscanf(line, "%s %s", file_user, file_ip) == 2) {
            if (strcmp(file_user, username) == 0) {
                strcpy(hostname, file_ip);
                fclose(fp);

                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}


int validate_expiry(long long input_time, long long validity) {

    time_t current_time = time(NULL);
    if (input_time + validity > current_time) {
        return 1;
    }
    return 0;

}


void extract_username(FILE* certificate_file, char* username) {

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);

    X509_NAME* subject = X509_get_subject_name(certificate);
    X509_NAME_get_text_by_NID(subject, NID_commonName, username, MAX_USERNAME_LEN);

    X509_free(certificate);
}


int encrypt_message(char* message, int message_len, unsigned char* encrypted_message, int* encrypted_message_len, unsigned char* session_key) {

    struct timespec encyption_start_time, encyption_end_time;
    clock_gettime(CLOCK_MONOTONIC, &encyption_start_time);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        printf("[-] Failed to create cipher context\n");
        return -1;
    }

    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));

    int enc_out_len = 0;

    memcpy(encrypted_message, iv, sizeof(iv));
    *encrypted_message_len = sizeof(iv);

    EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, session_key, iv);
    EVP_EncryptUpdate(context, encrypted_message + sizeof(iv), &enc_out_len, (unsigned char*)message, message_len);
    *encrypted_message_len += enc_out_len;

    EVP_EncryptFinal_ex(context, encrypted_message + sizeof(iv) + enc_out_len, &enc_out_len);
    *encrypted_message_len += enc_out_len;

    EVP_CIPHER_CTX_free(context);

    clock_gettime(CLOCK_MONOTONIC, &encyption_end_time);
    printf("-\nTime for data encryption: %f\n-\n", get_time_difference(encyption_start_time, encyption_end_time));

    return 1;
}


int decrypt_message(char* encrypted_message, int encrypted_message_len, unsigned char* decrypted_message, int* decrypted_message_len, unsigned char* session_key) {

    struct timespec decryption_start_time, decryption_end_time;
    clock_gettime(CLOCK_MONOTONIC, &decryption_start_time);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        printf("[-] Failed to create cipher context\n");
        return -1;
    }

    unsigned char iv[16];
    memcpy(iv, encrypted_message, sizeof(iv));

    int dec_out_len = 0;

    EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), NULL, session_key, iv);
    EVP_DecryptUpdate(context, decrypted_message, &dec_out_len, (unsigned char*)encrypted_message + sizeof(iv), encrypted_message_len - sizeof(iv));
    *decrypted_message_len = dec_out_len;

    EVP_DecryptFinal_ex(context, decrypted_message + dec_out_len, &dec_out_len);
    *decrypted_message_len += dec_out_len;

    EVP_CIPHER_CTX_free(context);

    clock_gettime(CLOCK_MONOTONIC, &decryption_end_time);
    printf("-\nTime for data decryption: %f\n-\n", get_time_difference(decryption_start_time, decryption_end_time));

    return 1;
}


int send_certificate(long long socket_descriptor, int packet_identifier,char* cert_path) {

    int read_bytes = 0;
    char send_buffer[BUFFER_SIZE];

    memcpy(send_buffer, &packet_identifier, sizeof(packet_identifier));

    if (packet_identifier) {

        FILE* my_cert = fopen(cert_path, "rb");

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


void extract_decrypted_session_key(char session_key_path[MAX_FILE_PATH], long long* generated_on, unsigned char **plaintext) {

    FILE* session_key_file = fopen(session_key_path, "rb");
    if (session_key_file == NULL) {
        printf("[-] Failed to open session key file\n");
    }

    fread(*plaintext, 1, SESSION_KEY_LEN, session_key_file);
    fseek(session_key_file, SESSION_KEY_LEN+1, SEEK_SET);
    fscanf(session_key_file, "%lld", generated_on);

    fclose(session_key_file);

    printf("[+] session key read from file\n");
}


void extract_encrypted_session_key(char session_key_path[256], size_t* decrypted_session_key_len, long long* generated_on, unsigned char **plaintext) {

    unsigned char encrypted_session_key[256];

    FILE* session_key_file = fopen(session_key_path, "rb");
    fread(encrypted_session_key, 1, 256, session_key_file);
    fseek(session_key_file, 257, SEEK_SET);
    fscanf(session_key_file, "%lld", generated_on);

    FILE* secret_file = fopen("./credentials/secret.pem", "rb");
    EVP_PKEY* private_key = PEM_read_PrivateKey(secret_file, NULL, NULL, NULL);

    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(private_key, NULL);
    EVP_PKEY_decrypt_init(context);
    EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_decrypt(context, NULL, decrypted_session_key_len, encrypted_session_key, sizeof(encrypted_session_key));

    *plaintext = malloc(*decrypted_session_key_len);

    EVP_PKEY_decrypt(context, *plaintext, decrypted_session_key_len, encrypted_session_key, sizeof(encrypted_session_key));

}


void create_session_key(unsigned char *session_key, X509 *cert, char session_key_path[MAX_FILE_PATH], char decrypted_session_key_path[MAX_FILE_PATH]) {

    struct timespec session_start_time, session_end_time;
    clock_gettime(CLOCK_MONOTONIC, &session_start_time);

    RAND_bytes(session_key, SESSION_KEY_LEN);

    size_t encrypted_session_key_len = 0;

    EVP_PKEY* public_key = X509_get_pubkey(cert);
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(public_key, NULL);

    free(cert);

    EVP_PKEY_encrypt_init(context);
    EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_encrypt(context, NULL, &encrypted_session_key_len, session_key, SESSION_KEY_LEN);

    unsigned char* encrypted_session_key = malloc(encrypted_session_key_len);

    EVP_PKEY_encrypt(context, encrypted_session_key, &encrypted_session_key_len, session_key, SESSION_KEY_LEN);

    time_t current_time = time(NULL);

    FILE* session_key_file = fopen(session_key_path, "wb");
    fwrite(encrypted_session_key, 1, encrypted_session_key_len, session_key_file);

    fprintf(session_key_file, "\n%lld", current_time);
    fclose(session_key_file);

    FILE* decrypted_session_key_file = fopen(decrypted_session_key_path, "wb");
    fwrite(session_key, 1, SESSION_KEY_LEN, decrypted_session_key_file);
    fprintf(decrypted_session_key_file, "\n%lld", current_time);
    fclose(decrypted_session_key_file);

    free(encrypted_session_key);

    clock_gettime(CLOCK_MONOTONIC, &session_end_time);

    printf("-\n Time for session key generation/renewal + RSA encrypt: %f\n-\n", get_time_difference(session_start_time,session_end_time));

}

int receive_certificate(long long socket_descriptor, int packet_identifier, char* username, unsigned char* session_key) {

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

    FILE* temp_crt_file = fopen(crt_file_path, "wb+");

    fwrite(receive_buffer + 2*sizeof(packet_identifier), 1, read_bytes - 2*sizeof(packet_identifier), temp_crt_file);

    payload_size = payload_size - read_bytes - 2*sizeof(packet_identifier);
    while (payload_size > 0) {
        read_bytes = recv(socket_descriptor, receive_buffer, BUFFER_SIZE, 0);
        fwrite(receive_buffer, 1, read_bytes, temp_crt_file);

        payload_size -= read_bytes;
    }

    fseek(temp_crt_file, 0, SEEK_SET);
    X509* cert = PEM_read_X509(temp_crt_file, NULL, NULL, NULL);

    char certificate_username[MAX_USERNAME_LEN];

    fseek(temp_crt_file, 0, SEEK_SET);
    extract_username(temp_crt_file, certificate_username);

    fclose(temp_crt_file);

    if (strcmp(certificate_username, username) == 0) {

        char session_key_path[MAX_FILE_PATH] = "./trust_store/session_";
        strcat(session_key_path, username);
        strcat(session_key_path, ".txt");

        long long generated_on;

        // FILE* sesson_check = fopen(session_key_path, "rb");
        // if (sesson_check != NULL) {
        //     fclose(sesson_check);
        //     extract_decrypted_session_key(session_key_path, &generated_on, &session_key);
        //     if (validate_expiry(generated_on, 5*60) > 0) {
        //         return 1;
        //     }
        // }
        // fclose(sesson_check);

        char encrypted_session_key_path[MAX_FILE_PATH] = "./trust_store/enc_session_";
        strcat(encrypted_session_key_path, username);
        strcat(encrypted_session_key_path, ".txt");

        create_session_key(session_key, cert, encrypted_session_key_path, session_key_path);

        return 1;
    }

    remove(crt_file_path);

    printf("invalid certificate received\n");
    //end lock here

    return 0;
}
