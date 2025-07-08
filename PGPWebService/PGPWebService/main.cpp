#include "civetweb.h"
#include "pgp_wrapper.h"
#include <string>

// Handler for /encrypt
int encrypt_handler(struct mg_connection *conn, void *cbdata) {
    char post_data[1024];
    int post_data_len = mg_read(conn, post_data, sizeof(post_data));
    post_data[post_data_len] = '\0';

	std::string encrypted_text = encrypt_text(post_data);	

    mg_printf(conn,
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n%s",
              encrypted_text.c_str());
    return 200;
}

// Handler for /decrypt
int decrypt_handler(struct mg_connection *conn, void *cbdata) {
    char post_data[1024];
    int post_data_len = mg_read(conn, post_data, sizeof(post_data));
    post_data[post_data_len] = '\0';

    std::string decrypted_text = decrypt_text(post_data);

    mg_printf(conn,
              "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n%s",
              decrypted_text.c_str());
    return 200;
}

int main() {
    const char *options[] = {
        "document_root", ".", "listening_ports", "8080", 0};

    struct mg_callbacks callbacks;
    struct mg_context *ctx;

    memset(&callbacks, 0, sizeof(callbacks));
    ctx = mg_start(&callbacks, 0, options);

    mg_set_request_handler(ctx, "/encrypt", encrypt_handler, 0);
    mg_set_request_handler(ctx, "/decrypt", decrypt_handler, 0);

    printf("Server started on port 8080\n");
    getchar();  // Wait for user input to stop the server

    mg_stop(ctx);
    return 0;
}
