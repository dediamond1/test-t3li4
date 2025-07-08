#ifndef PGP_WRAPPER_H
#define PGP_WRAPPER_H

#include <string>

// Encripta texto plano usando la clave pública
std::string encrypt_text(const std::string& plain_text);

// Desencripta texto cifrado usando la clave privada
std::string decrypt_text(const std::string& encrypted_text);

#endif // PGP_WRAPPER_H
