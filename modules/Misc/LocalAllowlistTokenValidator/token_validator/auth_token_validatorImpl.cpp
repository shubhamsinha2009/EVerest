#include <algorithm>
#include <cctype>
#include <fstream>

#include "auth_token_validatorImpl.hpp"

namespace module {
namespace token_validator {

static std::string normalize_token(std::string str) {
    // 1. Strip comments starting with '#'
    size_t comment_pos = str.find_first_of("#");
    if (comment_pos != std::string::npos) {
        str = str.substr(0, comment_pos);
    }

    // 2. Strip leading/trailing whitespace, \r, \n
    while (!str.empty() && (str.back() == '\r' || str.back() == '\n' || std::isspace(str.back()))) {
        str.pop_back();
    }
    size_t start = 0;
    while (start < str.size() && std::isspace(str[start])) {
        start++;
    }
    str = str.substr(start);

    // 3. Strip optional "VID:" or "vid:" prefix
    if (str.rfind("VID:", 0) == 0 || str.rfind("vid:", 0) == 0) {
        str = str.substr(4);
    }

    // 4. Remove all separators: colons ':', hyphens '-', and spaces ' '
    str.erase(std::remove_if(str.begin(), str.end(), [](char c) {
        return c == ':' || c == '-' || c == ' ';
    }), str.end());

    // 5. Convert to uppercase for strict case-insensitive equality
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return std::toupper(c);
    });

    return str;
}

void auth_token_validatorImpl::init() {
}

void auth_token_validatorImpl::ready() {
}

types::authorization::ValidationResult
auth_token_validatorImpl::handle_validate_token(types::authorization::ProvidedIdToken& provided_token) {
    types::authorization::ValidationResult result;
    result.authorization_status = types::authorization::AuthorizationStatus::Invalid;

    std::string target_token = normalize_token(provided_token.id_token.value);
    if (target_token.empty()) {
        return result;
    }

    // load file each time we validate so that EVerest requires no restart when the file is changed
    std::ifstream file;

    try {
        file.open(mod->config.allowlist_file);
        while (!file.eof()) {
            std::string line;
            getline(file, line);
            std::string norm_line = normalize_token(line);
            if (!norm_line.empty() && norm_line == target_token) {
                result.authorization_status = types::authorization::AuthorizationStatus::Accepted;
                break;
            }
        }
    } catch (std::ifstream::failure e) {
        EVLOG_error << "Error opening/reading file " + mod->config.allowlist_file;
    }

    file.close();

    return result;
}

} // namespace token_validator
} // namespace module
