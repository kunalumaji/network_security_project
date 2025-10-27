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

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


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


int main() {

    // generate_csr("kunalumaji");

    get_cert("kunalumaji", "127.0.0.1");

    if (verify_cert("./trust_store/me.crt")) {
        printf("verified certificate\n");
    }
    else
        printf("invalid certificate");

    return 0;
}