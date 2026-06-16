// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "auth_token_validatorImpl.hpp"

#include <everest/helpers/helpers.hpp>
#include <algorithm>
#include <sstream>

namespace module {
namespace main {

void auth_token_validatorImpl::init() {
}

void auth_token_validatorImpl::ready() {
}

types::authorization::ValidationResult
auth_token_validatorImpl::handle_validate_token(types::authorization::ProvidedIdToken& provided_token) {
    EVLOG_info << "Got validation request for token: " << provided_token.id_token.value;
    types::authorization::ValidationResult ret;

    bool token_allowed = true;

    if (!config.allowed_tokens.empty()) {
        token_allowed = false;

        // Convert provided token to lowercase
        std::string token_lower = provided_token.id_token.value;
        std::transform(token_lower.begin(), token_lower.end(), token_lower.begin(), ::tolower);

        // Parse comma-separated allowed tokens
        std::stringstream ss(config.allowed_tokens);
        std::string item;
        while (std::getline(ss, item, ',')) {
            // Strip leading/trailing spaces
            size_t first = item.find_first_not_of(" \t\r\n");
            if (first == std::string::npos) continue;
            size_t last = item.find_last_not_of(" \t\r\n");
            std::string allowed = item.substr(first, (last - first + 1));

            // Convert to lowercase
            std::transform(allowed.begin(), allowed.end(), allowed.begin(), ::tolower);

            // Match (prefix match or exact match)
            if (!allowed.empty() && token_lower.rfind(allowed, 0) == 0) {
                token_allowed = true;
                break;
            }
        }
    }

    if (token_allowed) {
        ret.authorization_status = types::authorization::string_to_authorization_status(config.validation_result);
        EVLOG_info << "Token " << provided_token.id_token.value << " is ALLOWED. Returning validation status: " << config.validation_result;
    } else {
        ret.authorization_status = types::authorization::AuthorizationStatus::Invalid;
        EVLOG_warning << "Token " << provided_token.id_token.value << " is BLOCKED (not in allowed list: " << config.allowed_tokens << ")";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(static_cast<int>(config.sleep * 1000)));
    return ret;
}

} // namespace main
} // namespace module
