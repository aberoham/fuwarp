#!/usr/bin/env bash

# Check if we're being run with sh instead of bash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Error: This script requires bash, but you're running it with sh"
    echo "Please run it with one of these commands:"
    echo "  bash $0"
    echo "  ./$0"
    echo "  chmod +x $0 && ./$0"
    exit 1
fi

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Certificate details
CERT_PATH="$HOME/.cloudflare-ca.pem"
SHELL_MODIFIED=false
CERT_FINGERPRINT=""  # Cache for certificate fingerprint

# Mode flags
MODE="status"  # Default mode is status checking
DEBUG="false"  # Debug mode flag

# Parse command line arguments
for arg in "$@"; do
    case $arg in
        --fix)
            MODE="install"
            shift
            ;;
        --debug|--verbose)
            DEBUG="true"
            shift
            ;;
        --help|-h)
            echo "Cloudflare Certificate Installation Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --fix            Actually make changes (default is status check only)"
            echo "  --debug          Show detailed debug information"
            echo "  --verbose        Same as --debug"
            echo "  --help, -h       Show this help message"
            echo ""
            echo "By default, this script runs in status check mode and shows what is"
            echo "currently configured without making any changes."
            exit 0
            ;;
    esac
done

# Function to check if we're in install mode
is_install_mode() {
    [ "$MODE" = "install" ]
}

# Function to check if we're in debug mode
is_debug_mode() {
    [ "$DEBUG" = "true" ]
}

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status() {
    echo -e "${BLUE}[STATUS]${NC} $1"
}

print_action() {
    echo -e "${YELLOW}[ACTION]${NC} $1"
}

print_debug() {
    if is_debug_mode; then
        echo -e "${BLUE}[DEBUG]${NC} $1" >&2
    fi
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a file/directory is writable
is_writable() {
    local path="$1"
    if [ -f "$path" ]; then
        # File exists, check if writable
        [ -w "$path" ]
    elif [ -d "$(dirname "$path")" ]; then
        # Directory exists, check if we can create files in it
        [ -w "$(dirname "$path")" ]
    else
        # Path doesn't exist, check parent directories
        local parent="$(dirname "$path")"
        while [ ! -d "$parent" ] && [ "$parent" != "/" ]; do
            parent="$(dirname "$parent")"
        done
        [ -w "$parent" ]
    fi
}

# Function to suggest alternative path
suggest_user_path() {
    local original_path="$1"
    local purpose="$2"
    local filename=$(basename "$original_path")
    
    # Create a user-controlled alternative
    echo "$HOME/.cloudflare-warp/${purpose}/${filename}"
}

# Function to detect the current shell
detect_shell() {
    if [ -n "${SHELL:-}" ]; then
        case "$SHELL" in
            */bash) echo "bash" ;;
            */zsh) echo "zsh" ;;
            */fish) echo "fish" ;;
            *) echo "unknown" ;;
        esac
    else
        echo "unknown"
    fi
}

# Function to get shell config file
get_shell_config() {
    local shell_type="$1"
    case "$shell_type" in
        bash)
            if [ -f "$HOME/.bashrc" ]; then
                echo "$HOME/.bashrc"
            elif [ -f "$HOME/.bash_profile" ]; then
                echo "$HOME/.bash_profile"
            else
                echo "$HOME/.profile"
            fi
            ;;
        zsh)
            echo "$HOME/.zshrc"
            ;;
        fish)
            echo "$HOME/.config/fish/config.fish"
            ;;
        *)
            echo "$HOME/.profile"
            ;;
    esac
}

# Function to get certificate fingerprint (cached)
get_cert_fingerprint() {
    if [ -z "$CERT_FINGERPRINT" ]; then
        if [ -f "$CERT_PATH" ]; then
            CERT_FINGERPRINT=$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
            print_debug "Cached certificate fingerprint: $CERT_FINGERPRINT"
        fi
    fi
    echo "$CERT_FINGERPRINT"
}

# Fast certificate check using grep (for status mode)
# Returns 0 if certificate likely exists, 1 if not
certificate_likely_exists_in_file() {
    local cert_file="$1"
    local target_file="$2"
    
    if [ ! -f "$target_file" ] || [ ! -f "$cert_file" ]; then
        return 1
    fi
    
    # Method 1: Try to match by subject CN (most reliable for status check)
    local cert_cn
    cert_cn=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -o 'CN=[^,]*' | cut -d= -f2-)
    
    if [ -n "$cert_cn" ] && grep -qF "$cert_cn" "$target_file" 2>/dev/null; then
        print_debug "Certificate likely exists in $target_file (found matching CN: $cert_cn)"
        return 0
    fi
    
    # Method 2: Try to match certificate content
    local cert_content
    cert_content=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$cert_file" | grep -v -- "-----" | tr -d '\n' | cut -c1-100)
    
    if [ -n "$cert_content" ]; then
        # Extract content from target file and compare
        local target_certs
        target_certs=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$target_file" | grep -v -- "-----" | tr -d '\n')
        
        if [[ "$target_certs" == *"$cert_content"* ]]; then
            print_debug "Certificate likely exists in $target_file (found matching content)"
            return 0
        fi
    fi
    
    return 1
}

# Function to check if a certificate already exists in a file (thorough check for install mode)
# Returns 0 if certificate exists, 1 if not
certificate_exists_in_file() {
    local cert_file="$1"
    local target_file="$2"
    
    if [ ! -f "$target_file" ]; then
        return 1
    fi
    
    # In status mode, use the fast check
    if ! is_install_mode; then
        certificate_likely_exists_in_file "$cert_file" "$target_file"
        return $?
    fi
    
    # Get cached fingerprint
    local cert_fingerprint=$(get_cert_fingerprint)
    
    if [ -z "$cert_fingerprint" ]; then
        return 1
    fi
    
    # For install mode, do the thorough check
    local temp_cert=$(mktemp)
    local in_cert=false
    local found=false
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^-----BEGIN\ CERTIFICATE----- ]]; then
            in_cert=true
            echo "$line" > "$temp_cert"
        elif [[ "$line" =~ ^-----END\ CERTIFICATE----- ]]; then
            echo "$line" >> "$temp_cert"
            if [ "$in_cert" = true ]; then
                local file_fingerprint
                file_fingerprint=$(openssl x509 -in "$temp_cert" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
                if [ "$file_fingerprint" = "$cert_fingerprint" ]; then
                    found=true
                    break
                fi
            fi
            in_cert=false
        elif [ "$in_cert" = true ]; then
            echo "$line" >> "$temp_cert"
        fi
    done < "$target_file"
    
    rm -f "$temp_cert"
    
    if [ "$found" = true ]; then
        return 0
    else
        return 1
    fi
}

# Function to add export to shell config
add_to_shell_config() {
    local var_name="$1"
    local var_value="$2"
    local shell_config="$3"
    
    # Check if the export already exists
    if grep -q "export $var_name=" "$shell_config" 2>/dev/null; then
        print_warn "$var_name already exists in $shell_config"
        print_info "Current value: $(grep "export $var_name=" "$shell_config" | tail -1)"
        if ! is_install_mode; then
            print_action "Would ask to update $var_name in $shell_config"
            print_action "Would set: export $var_name=\"$var_value\""
        else
            read -p "Do you want to update it? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Comment out old entries
                sed -i.bak "s/^export $var_name=/#&/" "$shell_config"
                echo "export $var_name=\"$var_value\"" >> "$shell_config"
                SHELL_MODIFIED=true
                print_info "Updated $var_name in $shell_config"
            fi
        fi
    else
        if ! is_install_mode; then
            print_action "Would add to $shell_config:"
            print_action "export $var_name=\"$var_value\""
        else
            echo "export $var_name=\"$var_value\"" >> "$shell_config"
            SHELL_MODIFIED=true
            print_info "Added $var_name to $shell_config"
        fi
    fi
}

# Function to download and verify certificate
download_certificate() {
    print_info "Retrieving Cloudflare WARP certificate..."
    
    # Check if warp-cli is available
    if ! command_exists warp-cli; then
        print_error "warp-cli command not found. Please ensure Cloudflare WARP is installed."
        return 1
    fi
    
    # Get current certificate from warp-cli
    local warp_cert
    warp_cert=$(warp-cli certs --no-paginate 2>/dev/null)
    
    if [ -z "$warp_cert" ]; then
        print_error "Failed to get certificate from warp-cli"
        print_error "Make sure you are connected to Cloudflare WARP"
        return 1
    fi
    
    # Create a temp file for the WARP certificate
    local temp_cert=$(mktemp)
    echo "$warp_cert" > "$temp_cert"
    
    # Verify it's a valid PEM certificate
    if ! openssl x509 -noout -in "$temp_cert" 2>/dev/null; then
        print_error "Retrieved file is not a valid PEM certificate"
        rm -f "$temp_cert"
        return 1
    fi
    
    print_info "WARP certificate retrieved successfully"
    
    # Check if certificate needs to be saved to CERT_PATH
    local needs_save=false
    if [ -f "$CERT_PATH" ]; then
        # Check if existing cert matches WARP cert
        local existing_cert
        existing_cert=$(cat "$CERT_PATH" 2>/dev/null)
        
        if [ "$existing_cert" != "$warp_cert" ]; then
            print_info "Certificate at $CERT_PATH needs updating"
            needs_save=true
        else
            print_info "Certificate at $CERT_PATH is up to date"
        fi
    else
        print_info "Certificate will be saved to $CERT_PATH"
        needs_save=true
    fi
    
    # Save certificate if needed
    if [ "$needs_save" = true ]; then
        if ! is_install_mode; then
            print_action "Would save certificate to $CERT_PATH"
        else
            # Save certificate
            cp "$temp_cert" "$CERT_PATH"
            print_info "Certificate saved to $CERT_PATH"
        fi
    fi
    
    # Clean up
    rm -f "$temp_cert"
    
    # Cache the fingerprint for later use
    get_cert_fingerprint > /dev/null
    
    return 0
}

# Function to setup Node.js certificate
# NODE_EXTRA_CA_CERTS can contain multiple certificates and supplements (not replaces) system CAs
setup_node_cert() {
    if ! command_exists node; then
        return 0
    fi
    
    local shell_type=$(detect_shell)
    local shell_config=$(get_shell_config "$shell_type")
    local needs_setup=false
    
    if [ -n "${NODE_EXTRA_CA_CERTS:-}" ]; then
        if [ -f "$NODE_EXTRA_CA_CERTS" ]; then
            # Check if the file contains our certificate
            local cert_content=$(cat "$CERT_PATH")
            local file_content=$(cat "$NODE_EXTRA_CA_CERTS" 2>/dev/null || echo "")
            
            if [[ "$file_content" == *"$cert_content"* ]] || [ "$file_content" = "$cert_content" ]; then
                # Certificate already exists, nothing to do
                return 0
            else
                needs_setup=true
                print_info "Setting up Node.js certificate..."
                print_info "NODE_EXTRA_CA_CERTS is already set to: $NODE_EXTRA_CA_CERTS"
                
                # Check if we can write to the file
                if ! is_writable "$NODE_EXTRA_CA_CERTS"; then
                    print_error "Cannot write to $NODE_EXTRA_CA_CERTS (permission denied)"
                    local new_path=$(suggest_user_path "$NODE_EXTRA_CA_CERTS" "node")
                    print_warn "Suggesting alternative path: $new_path"
                if ! is_install_mode; then
                    print_action "Would create directory: $(dirname "$new_path")"
                    print_action "Would copy $NODE_EXTRA_CA_CERTS to $new_path"
                    print_action "Would append Cloudflare certificate to $new_path"
                    print_action "Would update NODE_EXTRA_CA_CERTS to point to $new_path"
                else
                    read -p "Do you want to use this alternative path? (Y/n) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                        mkdir -p "$(dirname "$new_path")"
                        if [ -f "$NODE_EXTRA_CA_CERTS" ]; then
                            cp "$NODE_EXTRA_CA_CERTS" "$new_path" 2>/dev/null || touch "$new_path"
                        fi
                        if ! certificate_exists_in_file "$CERT_PATH" "$new_path"; then
                            cat "$CERT_PATH" >> "$new_path"
                        fi
                        add_to_shell_config "NODE_EXTRA_CA_CERTS" "$new_path" "$shell_config"
                        print_info "Created new certificate bundle at $new_path"
                    fi
                fi
            else
                    if ! is_install_mode; then
                        print_action "Would append Cloudflare certificate to $NODE_EXTRA_CA_CERTS"
                    else
                        print_info "Appending Cloudflare certificate to $NODE_EXTRA_CA_CERTS"
                        if ! certificate_exists_in_file "$CERT_PATH" "$NODE_EXTRA_CA_CERTS"; then
                            cat "$CERT_PATH" >> "$NODE_EXTRA_CA_CERTS"
                        else
                            print_info "Certificate already exists in $NODE_EXTRA_CA_CERTS"
                        fi
                    fi
                fi
            fi
        else
            needs_setup=true
            print_info "Setting up Node.js certificate..."
            print_warn "NODE_EXTRA_CA_CERTS points to a non-existent file: $NODE_EXTRA_CA_CERTS"
            print_warn "Please fix this manually"
        fi
    else
        needs_setup=true
        print_info "Setting up Node.js certificate..."
        # NODE_EXTRA_CA_CERTS not set, create a new bundle
        local node_bundle="$HOME/.cloudflare-warp/node/ca-bundle.pem"
        if ! is_install_mode; then
            print_action "Would create Node.js CA bundle at $node_bundle"
            print_action "Would include Cloudflare certificate in the bundle"
            print_action "Would set NODE_EXTRA_CA_CERTS=$node_bundle"
        else
            print_info "Creating Node.js CA bundle at $node_bundle"
            mkdir -p "$(dirname "$node_bundle")"
            
            # Start with just the Cloudflare certificate
            # (NODE_EXTRA_CA_CERTS supplements system certs, doesn't replace them)
            cp "$CERT_PATH" "$node_bundle"
            
            add_to_shell_config "NODE_EXTRA_CA_CERTS" "$node_bundle" "$shell_config"
            print_info "Created Node.js CA bundle with Cloudflare certificate"
        fi
    fi
    
    # Setup npm cafile if npm is available
    if command_exists npm; then
        setup_npm_cafile
    fi
}

# Function to setup npm cafile
setup_npm_cafile() {
    # Check current npm cafile setting
    local current_cafile
    current_cafile=$(npm config get cafile 2>/dev/null || echo "")
    
    # npm needs a full CA bundle, not just a single certificate
    local npm_bundle="$HOME/.cloudflare-warp/npm/ca-bundle.pem"
    local needs_setup=false
    
    if [ -n "$current_cafile" ] && [ "$current_cafile" != "null" ] && [ "$current_cafile" != "undefined" ]; then
        if [ -f "$current_cafile" ]; then
            # Check if the file contains our certificate
            local cert_content=$(cat "$CERT_PATH")
            local file_content=$(cat "$current_cafile" 2>/dev/null || echo "")
            
            if [[ "$file_content" != *"$cert_content"* ]]; then
                needs_setup=true
                print_info "Configuring npm certificate..."
                print_warn "Current npm cafile doesn't contain Cloudflare certificate"
                
                # Check if we can write to the npm cafile
                if ! is_writable "$current_cafile"; then
                    print_error "Cannot write to npm cafile: $current_cafile (permission denied)"
                    print_warn "Will use alternative path: $npm_bundle"
                    if ! is_install_mode; then
                        print_action "Would create directory: $(dirname "$npm_bundle")"
                        print_action "Would create full CA bundle at $npm_bundle with system certificates and Cloudflare certificate"
                        print_action "Would run: npm config set cafile $npm_bundle"
                    else
                        mkdir -p "$(dirname "$npm_bundle")"
                        # Create a full bundle with system certs
                        if [ -f "/etc/ssl/cert.pem" ]; then
                            cp "/etc/ssl/cert.pem" "$npm_bundle"
                        elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
                            cp "/etc/ssl/certs/ca-certificates.crt" "$npm_bundle"
                        else
                            # Copy existing bundle if available
                            if [ -f "$current_cafile" ]; then
                                cp "$current_cafile" "$npm_bundle"
                            else
                                touch "$npm_bundle"
                            fi
                        fi
                        # Check if certificate already exists in bundle
                        if ! certificate_exists_in_file "$CERT_PATH" "$npm_bundle"; then
                            cat "$CERT_PATH" >> "$npm_bundle"
                        fi
                        npm config set cafile "$npm_bundle"
                        print_info "Created new npm cafile at $npm_bundle"
                    fi
                else
                    if ! is_install_mode; then
                        print_action "Would ask to append Cloudflare certificate to $current_cafile"
                    else
                        read -p "Do you want to append it to the existing cafile? (y/N) " -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            print_info "Appending Cloudflare certificate to $current_cafile"
                            if ! certificate_exists_in_file "$CERT_PATH" "$current_cafile"; then
                                cat "$CERT_PATH" >> "$current_cafile"
                            else
                                print_info "Certificate already exists in $current_cafile"
                            fi
                        fi
                    fi
                fi
            fi
        else
            needs_setup=true
            print_info "Configuring npm certificate..."
            print_warn "npm cafile points to non-existent file: $current_cafile"
            if ! is_install_mode; then
                print_action "Would create full CA bundle at $npm_bundle"
                print_action "Would run: npm config set cafile $npm_bundle"
            else
                read -p "Do you want to create a new CA bundle for npm? (Y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                    mkdir -p "$(dirname "$npm_bundle")"
                    # Create full bundle with system certs
                    if [ -f "/etc/ssl/cert.pem" ]; then
                        cp "/etc/ssl/cert.pem" "$npm_bundle"
                    elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
                        cp "/etc/ssl/certs/ca-certificates.crt" "$npm_bundle"
                    else
                        touch "$npm_bundle"
                    fi
                    if ! certificate_exists_in_file "$CERT_PATH" "$npm_bundle"; then
                        cat "$CERT_PATH" >> "$npm_bundle"
                    fi
                    npm config set cafile "$npm_bundle"
                    print_info "Created and configured npm cafile at $npm_bundle"
                fi
            fi
        fi
    else
        needs_setup=true
        print_info "Configuring npm certificate..."
        print_info "npm cafile is not configured"
        if ! is_install_mode; then
            print_action "Would create full CA bundle at $npm_bundle with system certificates and Cloudflare certificate"
            print_action "Would run: npm config set cafile $npm_bundle"
        else
            read -p "Do you want to configure npm with a CA bundle including Cloudflare certificate? (Y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                mkdir -p "$(dirname "$npm_bundle")"
                # Create full bundle with system certs
                if [ -f "/etc/ssl/cert.pem" ]; then
                    cp "/etc/ssl/cert.pem" "$npm_bundle"
                elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
                    cp "/etc/ssl/certs/ca-certificates.crt" "$npm_bundle"
                else
                    print_warn "Could not find system CA bundle, creating new bundle with only Cloudflare certificate"
                    touch "$npm_bundle"
                fi
                cat "$CERT_PATH" >> "$npm_bundle"
                npm config set cafile "$npm_bundle"
                print_info "Configured npm cafile to: $npm_bundle"
                
                # Verify the setting
                local verify_cafile
                verify_cafile=$(npm config get cafile 2>/dev/null || echo "")
                if [ "$verify_cafile" = "$npm_bundle" ]; then
                    print_info "npm cafile configured successfully"
                else
                    print_error "Failed to configure npm cafile"
                fi
            fi
        fi
    fi
}

# Function to setup Python certificate
setup_python_cert() {
    if ! command_exists python3 && ! command_exists python; then
        print_info "Python not found, skipping Python setup"
        return 0
    fi
    
    # Note: Unlike macOS curl which uses the system keychain via SecureTransport,
    # Python uses its own certificate bundle and needs explicit configuration
    local shell_type=$(detect_shell)
    local shell_config=$(get_shell_config "$shell_type")
    
    # Create combined certificate bundle for Python
    local python_bundle="$HOME/.python-ca-bundle.pem"
    local needs_setup=false
    
    if [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then
        if [ -f "$REQUESTS_CA_BUNDLE" ]; then
            # Check if we can write to the file
            if ! is_writable "$REQUESTS_CA_BUNDLE"; then
                print_error "Cannot write to $REQUESTS_CA_BUNDLE (permission denied)"
                local new_path=$(suggest_user_path "$REQUESTS_CA_BUNDLE" "python")
                print_warn "Suggesting alternative path: $new_path"
                if ! is_install_mode; then
                    print_action "Would create directory: $(dirname "$new_path")"
                    print_action "Would copy $REQUESTS_CA_BUNDLE to $new_path"
                    print_action "Would append Cloudflare certificate to $new_path"
                    print_action "Would update REQUESTS_CA_BUNDLE to point to $new_path"
                else
                    read -p "Do you want to use this alternative path? (Y/n) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                        mkdir -p "$(dirname "$new_path")"
                        if [ -f "$REQUESTS_CA_BUNDLE" ]; then
                            cp "$REQUESTS_CA_BUNDLE" "$new_path" 2>/dev/null || touch "$new_path"
                        fi
                        # Check if certificate already exists in the new path
                        if ! certificate_exists_in_file "$CERT_PATH" "$new_path"; then
                            cat "$CERT_PATH" >> "$new_path"
                        fi
                        needs_setup=true
                        print_info "Setting up Python certificate..."
                        print_info "REQUESTS_CA_BUNDLE is already set to: $REQUESTS_CA_BUNDLE"
                        add_to_shell_config "REQUESTS_CA_BUNDLE" "$new_path" "$shell_config"
                        add_to_shell_config "SSL_CERT_FILE" "$new_path" "$shell_config"
                        add_to_shell_config "CURL_CA_BUNDLE" "$new_path" "$shell_config"
                        print_info "Created new certificate bundle at $new_path"
                    fi
                fi
            else
                # Check if the file contains our certificate
                local cert_content=$(cat "$CERT_PATH")
                local file_content=$(cat "$REQUESTS_CA_BUNDLE" 2>/dev/null || echo "")
                
                if [[ "$file_content" != *"$cert_content"* ]]; then
                    needs_setup=true
                    print_info "Setting up Python certificate..."
                    print_info "REQUESTS_CA_BUNDLE is already set to: $REQUESTS_CA_BUNDLE"
                    if ! is_install_mode; then
                        print_action "Would append Cloudflare certificate to $REQUESTS_CA_BUNDLE"
                    else
                        print_info "Appending Cloudflare certificate to $REQUESTS_CA_BUNDLE"
                        if ! certificate_exists_in_file "$CERT_PATH" "$REQUESTS_CA_BUNDLE"; then
                            cat "$CERT_PATH" >> "$REQUESTS_CA_BUNDLE"
                        else
                            print_info "Certificate already exists in $REQUESTS_CA_BUNDLE"
                        fi
                    fi
                fi
            fi
        else
            needs_setup=true
            print_info "Setting up Python certificate..."
            print_info "REQUESTS_CA_BUNDLE is already set to: $REQUESTS_CA_BUNDLE"
            print_warn "REQUESTS_CA_BUNDLE points to a non-existent file: $REQUESTS_CA_BUNDLE"
        fi
    else
        needs_setup=true
        print_info "Setting up Python certificate..."
        if ! is_install_mode; then
            print_action "Would create Python CA bundle at $python_bundle"
            print_action "Would copy system certificates and append Cloudflare certificate"
        else
            print_info "Creating Python CA bundle at $python_bundle"
            
            # Copy system certificates
            if [ -f "/etc/ssl/cert.pem" ]; then
                cp "/etc/ssl/cert.pem" "$python_bundle"
            elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
                cp "/etc/ssl/certs/ca-certificates.crt" "$python_bundle"
            else
                print_warn "Could not find system CA bundle, creating new bundle"
                touch "$python_bundle"
            fi
            
            # Append Cloudflare certificate
            # Check if certificate already exists in bundle
            if ! certificate_exists_in_file "$CERT_PATH" "$python_bundle"; then
                cat "$CERT_PATH" >> "$python_bundle"
            fi
        fi
        
        add_to_shell_config "REQUESTS_CA_BUNDLE" "$python_bundle" "$shell_config"
        add_to_shell_config "SSL_CERT_FILE" "$python_bundle" "$shell_config"
        add_to_shell_config "CURL_CA_BUNDLE" "$python_bundle" "$shell_config"
    fi
}

# Function to setup gcloud certificate
setup_gcloud_cert() {
    if ! command_exists gcloud; then
        print_info "gcloud not found, skipping gcloud setup"
        return 0
    fi
    
    local gcloud_cert_dir="$HOME/.config/gcloud/certs"
    local gcloud_bundle="$gcloud_cert_dir/combined-ca-bundle.pem"
    local needs_setup=false
    
    # Check current gcloud custom CA setting
    local current_ca_file
    current_ca_file=$(gcloud config get-value core/custom_ca_certs_file 2>/dev/null || echo "")
    
    # Check if gcloud needs configuration
    if [ -z "$current_ca_file" ] || [ "$current_ca_file" = "" ]; then
        needs_setup=true
    elif [ -f "$current_ca_file" ]; then
        # Check if current CA file contains our certificate
        local cert_content=$(cat "$CERT_PATH")
        local file_content=$(cat "$current_ca_file" 2>/dev/null || echo "")
        if [[ "$file_content" != *"$cert_content"* ]]; then
            needs_setup=true
        fi
    else
        needs_setup=true
    fi
    
    if [ "$needs_setup" = false ]; then
        return 0
    fi
    
    print_info "Setting up gcloud certificate..."
    
    # Create directory if it doesn't exist
    if is_install_mode; then
        mkdir -p "$gcloud_cert_dir"
    fi
    
    if [ -n "$current_ca_file" ] && [ "$current_ca_file" != "$gcloud_bundle" ]; then
        print_warn "gcloud is already configured with custom CA: $current_ca_file"
        
        # Check if the current CA file is writable
        if [ -f "$current_ca_file" ] && ! is_writable "$current_ca_file"; then
            print_error "Cannot write to current gcloud CA file: $current_ca_file (permission denied)"
            print_warn "Will use alternative path: $gcloud_bundle"
            if ! is_install_mode; then
                print_action "Would create new gcloud CA bundle at $gcloud_bundle"
            fi
            # Continue with the new path
        else
            if ! is_install_mode; then
                print_action "Would ask to update gcloud CA configuration"
                return 0
            else
                read -p "Do you want to update it? (y/N) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    return 0
                fi
            fi
        fi
    fi
    
    if ! is_install_mode; then
        print_action "Would create directory: $gcloud_cert_dir"
        print_action "Would create gcloud CA bundle at $gcloud_bundle"
        print_action "Would copy system certificates and append Cloudflare certificate"
        print_action "Would run: gcloud config set core/custom_ca_certs_file $gcloud_bundle"
    else
        # Create combined bundle
        print_info "Creating gcloud CA bundle at $gcloud_bundle"
        
        # Copy system certificates
        if [ -f "/etc/ssl/cert.pem" ]; then
            cp "/etc/ssl/cert.pem" "$gcloud_bundle"
        elif [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
            cp "/etc/ssl/certs/ca-certificates.crt" "$gcloud_bundle"
        else
            touch "$gcloud_bundle"
        fi
        
        # Append Cloudflare certificate
        # Check if certificate already exists in bundle
        if ! certificate_exists_in_file "$CERT_PATH" "$gcloud_bundle"; then
            cat "$CERT_PATH" >> "$gcloud_bundle"
        fi
        
        # Configure gcloud
        if gcloud config set core/custom_ca_certs_file "$gcloud_bundle" 2>/dev/null; then
            print_info "gcloud configured successfully"
            # Only run diagnostics in real mode when we actually changed settings
            if [ "$needs_setup" = true ]; then
                print_info "Running gcloud diagnostics..."
                gcloud info --run-diagnostics 2>&1 | grep -E "(PASS|FAIL|ERROR)" || true
            fi
        else
            print_error "Failed to configure gcloud"
        fi
    fi
}

# Function to setup Java/JVM certificate
setup_java_cert() {
    if ! command_exists java && ! command_exists keytool; then
        return 0
    fi
    
    # Find JAVA_HOME
    if [ -z "${JAVA_HOME:-}" ]; then
        if command_exists java; then
            JAVA_HOME=$(java -XshowSettings:properties -version 2>&1 | grep 'java.home' | awk -F'=' '{print $2}' | tr -d ' ')
            export JAVA_HOME
        else
            print_warn "Could not determine JAVA_HOME"
            return 1
        fi
    fi
    
    local cacerts="$JAVA_HOME/lib/security/cacerts"
    if [ ! -f "$cacerts" ]; then
        cacerts="$JAVA_HOME/jre/lib/security/cacerts"
    fi
    
    if [ ! -f "$cacerts" ]; then
        print_error "Could not find Java cacerts file"
        return 1
    fi
    
    # Check if certificate already exists
    if keytool -list -alias cloudflare-zerotrust -cacerts -storepass changeit 2>/dev/null | grep -q cloudflare-zerotrust; then
        # Certificate already exists, nothing to do
        return 0
    else
        print_info "Setting up Java certificate..."
        print_info "Adding certificate to Java keystore: $cacerts"
        
        if ! is_install_mode; then
            print_action "Would import certificate to Java keystore: $cacerts"
            print_action "Would run: keytool -import -trustcacerts -alias cloudflare-zerotrust -file $CERT_PATH -cacerts -storepass changeit -noprompt"
        else
            if keytool -import -trustcacerts -alias cloudflare-zerotrust -file "$CERT_PATH" -cacerts -storepass changeit -noprompt 2>/dev/null; then
                print_info "Certificate added to Java keystore successfully"
            else
                print_warn "Failed to add certificate to Java keystore (may require sudo)"
            fi
        fi
    fi
}

# Function to setup DBeaver certificate
setup_dbeaver_cert() {
    local dbeaver_keytool="/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/bin/keytool"
    local dbeaver_cacerts="/Applications/DBeaver.app/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
    
    # Check if DBeaver is installed at the default location
    if [ ! -f "$dbeaver_keytool" ]; then
        return 0
    fi
    
    # Check if the cacerts file exists
    if [ ! -f "$dbeaver_cacerts" ]; then
        print_error "DBeaver cacerts file not found at: $dbeaver_cacerts"
        return 1
    fi
    
    # Check if certificate already exists
    if "$dbeaver_keytool" -list -alias cloudflare-zerotrust -keystore "$dbeaver_cacerts" -storepass changeit 2>/dev/null | grep -q cloudflare-zerotrust; then
        # Certificate already exists, nothing to do
        return 0
    else
        print_info "Setting up DBeaver certificate..."
        print_info "Found DBeaver at default install location"
        
        if ! is_install_mode; then
            print_action "Would import certificate to DBeaver keystore: $dbeaver_cacerts"
            print_action "Would run: $dbeaver_keytool -import -trustcacerts -alias cloudflare-zerotrust -file $CERT_PATH -keystore $dbeaver_cacerts -storepass changeit -noprompt"
        else
            print_info "Adding certificate to DBeaver keystore..."
            if "$dbeaver_keytool" -import -trustcacerts -alias cloudflare-zerotrust -file "$CERT_PATH" -keystore "$dbeaver_cacerts" -storepass changeit -noprompt 2>/dev/null; then
                print_info "Certificate added to DBeaver keystore successfully"
            else
                print_warn "Failed to add certificate to DBeaver keystore (may require sudo)"
                print_warn "You may need to run: sudo ./fuwarp.sh --fix"
            fi
        fi
    fi
}

# Function to setup Podman certificate
setup_podman_cert() {
    if ! command_exists podman; then
        return 0
    fi
    
    print_info "Setting up Podman certificate..."
    
    # Check if podman machine exists
    if ! podman machine list 2>/dev/null | grep -q "Currently running"; then
        print_warn "No Podman machine is currently running"
        print_info "Please start a Podman machine first with: podman machine start"
        return 0
    fi
    
    if ! is_install_mode; then
        print_action "Would copy certificate to Podman VM"
        print_action "Would run: podman machine ssh 'sudo tee /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem' < $CERT_PATH"
        print_action "Would run: podman machine ssh 'sudo update-ca-trust'"
    else
        print_info "Copying certificate to Podman VM..."
        
        # Copy certificate into Podman VM
        if podman machine ssh "sudo tee /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem" < "$CERT_PATH" >/dev/null 2>&1; then
            # Update CA trust
            if podman machine ssh "sudo update-ca-trust" 2>/dev/null; then
                print_info "Podman certificate installed successfully"
            else
                print_error "Failed to update CA trust in Podman VM"
            fi
        else
            print_error "Failed to copy certificate to Podman VM"
        fi
    fi
}

# Function to setup Rancher certificate
setup_rancher_cert() {
    if ! command_exists rdctl; then
        return 0
    fi
    
    print_info "Setting up Rancher certificate..."
    
    if ! is_install_mode; then
        print_action "Would copy certificate to Rancher VM"
        print_action "Would run: rdctl shell sudo tee /usr/local/share/ca-certificates/cloudflare-warp.pem < $CERT_PATH"
        print_action "Would run: rdctl shell sudo update-ca-certificates"
    else
        print_info "Copying certificate to Rancher VM..."
        
        # Copy certificate into Rancher VM
        if rdctl shell sudo tee /usr/local/share/ca-certificates/cloudflare-warp.pem < "$CERT_PATH" >/dev/null 2>&1; then
            # Update CA certificates
            if rdctl shell sudo update-ca-certificates 2>/dev/null; then
                print_info "Rancher certificate installed successfully"
            else
                print_error "Failed to update CA certificates in Rancher VM"
            fi
        else
            print_error "Failed to copy certificate to Rancher VM"
        fi
    fi
}

# Function to setup Android Emulator certificate
setup_android_emulator_cert() {
    if ! command_exists adb || ! command_exists emulator; then
        print_info "Android SDK tools not found, skipping Android Emulator setup"
        return 0
    fi
    
    print_info "Checking for Android Emulator setup..."
    
    # Check if any emulator is running
    local running_devices
    running_devices=$(adb devices 2>/dev/null | grep -E "emulator-[0-9]+" | wc -l)
    
    if [ "$running_devices" -eq 0 ]; then
        print_info "No Android emulator is currently running"
        print_info "Please start an emulator with: emulator -avd <your_avd_id> -writable-system -selinux permissive"
        return 0
    fi
    
    print_warn "Android Emulator certificate installation requires a writable system partition"
    print_warn "Make sure your emulator was started with -writable-system flag"
    
    if ! is_install_mode; then
        print_action "Would restart ADB with root permissions: adb root"
        print_action "Would remount system partition: adb remount"
        print_action "Would push certificate to emulator: adb push $CERT_PATH /system/etc/security/cacerts/cloudflare-warp.pem"
        print_action "Would set permissions: adb shell chmod 644 /system/etc/security/cacerts/cloudflare-warp.pem"
        print_action "Would reboot emulator: adb reboot"
    else
        read -p "Do you want to install the certificate on the running Android emulator? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Installing certificate on Android emulator..."
            
            # Restart ADB with root
            if ! adb root 2>/dev/null; then
                print_error "Failed to restart ADB with root permissions"
                print_info "Make sure your emulator doesn't have Google Play Store"
                return 1
            fi
            
            # Remount system partition
            if ! adb remount 2>/dev/null; then
                print_error "Failed to remount system partition"
                print_info "Make sure emulator was started with -writable-system flag"
                return 1
            fi
            
            # Push certificate
            if adb push "$CERT_PATH" /system/etc/security/cacerts/cloudflare-warp.pem 2>/dev/null; then
                # Set permissions
                adb shell chmod 644 /system/etc/security/cacerts/cloudflare-warp.pem 2>/dev/null
                print_info "Certificate installed. Rebooting emulator..."
                adb reboot 2>/dev/null
                print_info "Android emulator certificate installed successfully"
            else
                print_error "Failed to push certificate to emulator"
            fi
        fi
    fi
}

# Function to verify if a tool can connect through WARP
verify_connection() {
    local tool_name="$1"
    local test_url="https://www.cloudflare.com"
    local result="UNKNOWN"
    local debug_output=""
    
    print_debug "Testing $tool_name connection to $test_url"
    
    case "$tool_name" in
        node)
            if command_exists node; then
                print_debug "Node.js found at: $(which node)"
                print_debug "NODE_EXTRA_CA_CERTS: ${NODE_EXTRA_CA_CERTS:-not set}"
                
                # Test SSL connection - we don't care about HTTP status, just SSL verification
                debug_output=$(node -e "
const https = require('https');
https.get('$test_url', {headers: {'User-Agent': 'Mozilla/5.0'}}, (res) => {
    console.error('HTTP Status:', res.statusCode);
    console.error('SSL authorized:', res.socket.authorized);
    // Any HTTP response is OK - we're testing SSL
    process.exit(0);
}).on('error', (err) => {
    console.error('Error:', err.message);
    console.error('Error code:', err.code);
    // Only exit with error for SSL issues
    process.exit(err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'CERT_HAS_EXPIRED' ? 1 : 0);
});
" 2>&1)
                
                if [ $? -eq 0 ]; then
                    result="WORKING"
                    print_debug "Node.js test succeeded"
                else
                    result="FAILED"
                    print_debug "Node.js test failed"
                fi
                
                if is_debug_mode && [ -n "$debug_output" ]; then
                    print_debug "Node.js output: $debug_output"
                fi
            else
                result="NOT_INSTALLED"
            fi
            ;;
        python)
            if command_exists python3; then
                print_debug "Python3 found at: $(which python3)"
                print_debug "Python version: $(python3 --version 2>&1)"
                print_debug "REQUESTS_CA_BUNDLE: ${REQUESTS_CA_BUNDLE:-not set}"
                print_debug "SSL_CERT_FILE: ${SSL_CERT_FILE:-not set}"
                
                # Test SSL connection with proper User-Agent header
                debug_output=$(python3 -c "
import urllib.request
import ssl
import sys
import os

print('Python SSL paths:', file=sys.stderr)
print(f'  REQUESTS_CA_BUNDLE: {os.environ.get(\"REQUESTS_CA_BUNDLE\", \"not set\")}', file=sys.stderr)
print(f'  SSL_CERT_FILE: {os.environ.get(\"SSL_CERT_FILE\", \"not set\")}', file=sys.stderr)
print(f'  Default cert paths: {ssl.get_default_verify_paths()}', file=sys.stderr)

try:
    req = urllib.request.Request('$test_url', headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, timeout=5)
    print(f'Success - HTTP {resp.code}', file=sys.stderr)
    exit(0)
except urllib.error.HTTPError as e:
    print(f'HTTP Error {e.code} - but SSL worked', file=sys.stderr)
    # HTTP errors (like 403) are OK - we're testing SSL
    exit(0)
except urllib.error.URLError as e:
    print(f'URL Error: {e.reason}', file=sys.stderr)
    # SSL errors mean the cert isn't trusted
    exit(1)
except ssl.SSLError as e:
    print(f'SSL Error: {e}', file=sys.stderr)
    exit(1)
except Exception as e:
    print(f'Unexpected error: {type(e).__name__}: {e}', file=sys.stderr)
    exit(1)
" 2>&1)
                
                if [ $? -eq 0 ]; then
                    result="WORKING"
                    print_debug "Python3 test succeeded"
                else
                    result="FAILED"
                    print_debug "Python3 test failed"
                fi
                
                if is_debug_mode && [ -n "$debug_output" ]; then
                    print_debug "Python3 output:"
                    echo "$debug_output" | while IFS= read -r line; do
                        print_debug "  $line"
                    done
                fi
            elif command_exists python; then
                print_debug "Python2 found at: $(which python)"
                print_debug "Python version: $(python --version 2>&1)"
                
                # Python 2 version
                debug_output=$(python -c "
import urllib2
import ssl
import sys
import os

print >> sys.stderr, 'Python SSL paths:'
print >> sys.stderr, '  REQUESTS_CA_BUNDLE:', os.environ.get('REQUESTS_CA_BUNDLE', 'not set')
print >> sys.stderr, '  SSL_CERT_FILE:', os.environ.get('SSL_CERT_FILE', 'not set')

try:
    req = urllib2.Request('$test_url', headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib2.urlopen(req, timeout=5)
    print >> sys.stderr, 'Success - HTTP', resp.code
    exit(0)
except urllib2.HTTPError as e:
    print >> sys.stderr, 'HTTP Error', e.code, '- but SSL worked'
    # HTTP errors (like 403) are OK - we're testing SSL
    exit(0)
except (urllib2.URLError, ssl.SSLError) as e:
    print >> sys.stderr, 'Error:', str(e)
    # SSL errors mean the cert isn't trusted
    exit(1)
except Exception as e:
    print >> sys.stderr, 'Unexpected error:', type(e).__name__, str(e)
    exit(1)
" 2>&1)
                
                if [ $? -eq 0 ]; then
                    result="WORKING"
                    print_debug "Python2 test succeeded"
                else
                    result="FAILED"
                    print_debug "Python2 test failed"
                fi
                
                if is_debug_mode && [ -n "$debug_output" ]; then
                    print_debug "Python2 output:"
                    echo "$debug_output" | while IFS= read -r line; do
                        print_debug "  $line"
                    done
                fi
            else
                result="NOT_INSTALLED"
            fi
            ;;
        curl)
            if command_exists curl; then
                print_debug "curl found at: $(which curl)"
                print_debug "curl version: $(curl --version | head -1)"
                print_debug "CURL_CA_BUNDLE: ${CURL_CA_BUNDLE:-not set}"
                
                # Test SSL connection - any HTTP response code is OK as long as SSL works
                if is_debug_mode; then
                    debug_output=$(curl -v -s -o /dev/null "$test_url" 2>&1)
                    curl_exit_code=$?
                    
                    if [ $curl_exit_code -eq 0 ]; then
                        result="WORKING"
                        print_debug "curl test succeeded"
                    else
                        result="FAILED"
                        print_debug "curl test failed with exit code: $curl_exit_code"
                    fi
                    
                    # Show relevant SSL info from curl verbose output
                    echo "$debug_output" | grep -E "(SSL|certificate|TLS)" | while IFS= read -r line; do
                        print_debug "curl: $line"
                    done
                else
                    if curl -s -o /dev/null "$test_url" 2>/dev/null; then
                        result="WORKING"
                    else
                        result="FAILED"
                    fi
                fi
            else
                result="NOT_INSTALLED"
            fi
            ;;
        wget)
            if command_exists wget; then
                print_debug "wget found at: $(which wget)"
                print_debug "wget config: ${HOME}/.wgetrc"
                
                if is_debug_mode; then
                    debug_output=$(wget --debug -O /dev/null "$test_url" 2>&1)
                    wget_exit_code=$?
                    
                    if [ $wget_exit_code -eq 0 ]; then
                        result="WORKING"
                        print_debug "wget test succeeded"
                    else
                        result="FAILED"
                        print_debug "wget test failed with exit code: $wget_exit_code"
                    fi
                    
                    # Show relevant SSL info
                    echo "$debug_output" | grep -E "(SSL|certificate|CA)" | while IFS= read -r line; do
                        print_debug "wget: $line"
                    done
                else
                    if wget -q -O /dev/null "$test_url" 2>/dev/null; then
                        result="WORKING"
                    else
                        result="FAILED"
                    fi
                fi
            else
                result="NOT_INSTALLED"
            fi
            ;;
    esac
    
    print_debug "Test result for $tool_name: $result"
    echo "$result"
}

# Function to check status of all configurations
check_all_status() {
    local has_issues=false
    local temp_warp_cert=""
    
    print_info "Checking Cloudflare WARP Certificate Status"
    print_info "==========================================="
    echo
    
    # First, get the current WARP certificate to use for all comparisons
    if command_exists warp-cli; then
        temp_warp_cert=$(mktemp)
        local warp_cert_content=$(warp-cli certs --no-paginate 2>/dev/null)
        if [ -n "$warp_cert_content" ]; then
            echo "$warp_cert_content" > "$temp_warp_cert"
            print_debug "Retrieved WARP certificate for comparison"
            # Pre-cache fingerprint for the WARP cert
            CERT_FINGERPRINT=$(openssl x509 -in "$temp_warp_cert" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
            print_debug "WARP certificate fingerprint: $CERT_FINGERPRINT"
        else
            print_error "Failed to retrieve WARP certificate"
            rm -f "$temp_warp_cert"
            return 1
        fi
    else
        print_error "warp-cli not found - cannot retrieve certificate"
        return 1
    fi
    
    # Check if WARP is connected
    print_status "Cloudflare WARP Connection:"
    if command_exists warp-cli; then
        local warp_status=$(warp-cli status 2>/dev/null | grep -i "status" || echo "unknown")
        if [[ "$warp_status" == *"Connected"* ]]; then
            print_info "  ✓ WARP is connected"
        else
            print_warn "  ✗ WARP is not connected"
            print_action "  Run: warp-cli connect"
            has_issues=true
        fi
    else
        print_error "  ✗ warp-cli not found"
        print_action "  Install Cloudflare WARP client"
        has_issues=true
    fi
    echo
    
    # Check certificate status
    print_status "Certificate Status:"
    
    # Check if WARP certificate is valid
    if openssl x509 -noout -checkend 86400 -in "$temp_warp_cert" 1> /dev/null 2>/dev/null; then
        print_info "  ✓ WARP certificate is valid"
        
        # Check where the certificate is currently stored
        local cert_locations=""
        local cert_found=false
        
        # Check common locations
        if [ -f "$CERT_PATH" ]; then
            local existing_cert=$(cat "$CERT_PATH" 2>/dev/null)
            local warp_cert_content=$(cat "$temp_warp_cert" 2>/dev/null)
            if [ "$existing_cert" = "$warp_cert_content" ]; then
                cert_locations="$cert_locations\n    - $CERT_PATH"
                cert_found=true
            fi
        fi
        
        # Check NODE_EXTRA_CA_CERTS
        if [ -n "${NODE_EXTRA_CA_CERTS:-}" ] && [ -f "$NODE_EXTRA_CA_CERTS" ]; then
            if certificate_exists_in_file "$temp_warp_cert" "$NODE_EXTRA_CA_CERTS"; then
                cert_locations="$cert_locations\n    - $NODE_EXTRA_CA_CERTS (NODE_EXTRA_CA_CERTS)"
                cert_found=true
            fi
        fi
        
        # Check REQUESTS_CA_BUNDLE
        if [ -n "${REQUESTS_CA_BUNDLE:-}" ] && [ -f "$REQUESTS_CA_BUNDLE" ]; then
            if certificate_exists_in_file "$temp_warp_cert" "$REQUESTS_CA_BUNDLE"; then
                cert_locations="$cert_locations\n    - $REQUESTS_CA_BUNDLE (REQUESTS_CA_BUNDLE)"
                cert_found=true
            fi
        fi
        
        # Check SSL_CERT_FILE
        if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
            if certificate_exists_in_file "$temp_warp_cert" "$SSL_CERT_FILE"; then
                cert_locations="$cert_locations\n    - $SSL_CERT_FILE (SSL_CERT_FILE)"
                cert_found=true
            fi
        fi
        
        if [ "$cert_found" = true ]; then
            print_info "  ✓ WARP certificate found in:$cert_locations"
        else
            print_warn "  ✗ WARP certificate not found in any configured location"
            print_action "    Run with --fix to install the certificate"
            has_issues=true
        fi
    else
        print_warn "  ✗ WARP certificate is expired or expiring soon"
        has_issues=true
    fi
    echo
    
    # Check Node.js configuration
    print_status "Node.js Configuration:"
    if command_exists node; then
        if [ -n "${NODE_EXTRA_CA_CERTS:-}" ]; then
            print_info "  NODE_EXTRA_CA_CERTS is set to: $NODE_EXTRA_CA_CERTS"
            if [ -f "$NODE_EXTRA_CA_CERTS" ]; then
                if certificate_exists_in_file "$temp_warp_cert" "$NODE_EXTRA_CA_CERTS"; then
                    print_info "  ✓ NODE_EXTRA_CA_CERTS contains current WARP certificate"
                    local verify_result=$(verify_connection "node")
                    if [ "$verify_result" = "WORKING" ]; then
                        print_info "  ✓ Node.js can connect through WARP"
                    else
                        print_warn "  ✗ Node.js connection test failed"
                        has_issues=true
                    fi
                else
                    print_warn "  ✗ NODE_EXTRA_CA_CERTS file exists but doesn't contain current WARP certificate"
                    print_action "    Run with --fix to append the certificate to this file"
                    has_issues=true
                fi
            else
                print_warn "  ✗ NODE_EXTRA_CA_CERTS points to non-existent file: $NODE_EXTRA_CA_CERTS"
                has_issues=true
            fi
        else
            print_warn "  ✗ NODE_EXTRA_CA_CERTS not configured"
            has_issues=true
        fi
        
        # Check npm
        if command_exists npm; then
            local npm_cafile=$(npm config get cafile 2>/dev/null || echo "")
            if [ -n "$npm_cafile" ] && [ "$npm_cafile" != "null" ] && [ "$npm_cafile" != "undefined" ]; then
                if [ -f "$npm_cafile" ]; then
                    if certificate_exists_in_file "$temp_warp_cert" "$npm_cafile"; then
                        print_info "  ✓ npm cafile contains current WARP certificate"
                    else
                        print_warn "  ✗ npm cafile doesn't contain current WARP certificate"
                        has_issues=true
                    fi
                else
                    print_warn "  ✗ npm cafile points to non-existent file"
                    has_issues=true
                fi
            else
                print_warn "  ✗ npm cafile not configured"
                has_issues=true
            fi
        fi
    else
        print_info "  - Node.js not installed"
    fi
    echo
    
    # Check Python configuration
    print_status "Python Configuration:"
    if command_exists python3 || command_exists python; then
        local python_configured=false
        
        if [ -n "${REQUESTS_CA_BUNDLE:-}" ]; then
            print_info "  REQUESTS_CA_BUNDLE is set to: $REQUESTS_CA_BUNDLE"
            if [ -f "$REQUESTS_CA_BUNDLE" ]; then
                if certificate_exists_in_file "$temp_warp_cert" "$REQUESTS_CA_BUNDLE"; then
                    print_info "  ✓ REQUESTS_CA_BUNDLE contains current WARP certificate"
                    python_configured=true
                else
                    print_warn "  ✗ REQUESTS_CA_BUNDLE file exists but doesn't contain current WARP certificate"
                    print_action "    Run with --fix to create a new bundle with both certificates"
                fi
            else
                print_warn "  ✗ REQUESTS_CA_BUNDLE points to non-existent file: $REQUESTS_CA_BUNDLE"
            fi
        fi
        
        # Also check SSL_CERT_FILE if set
        if [ -n "${SSL_CERT_FILE:-}" ]; then
            print_info "  SSL_CERT_FILE is set to: $SSL_CERT_FILE"
            if [ -f "$SSL_CERT_FILE" ]; then
                if certificate_exists_in_file "$temp_warp_cert" "$SSL_CERT_FILE"; then
                    print_info "  ✓ SSL_CERT_FILE contains current WARP certificate"
                    python_configured=true
                fi
            fi
        fi
        
        if [ "$python_configured" = true ]; then
            local verify_result=$(verify_connection "python")
            if [ "$verify_result" = "WORKING" ]; then
                print_info "  ✓ Python can connect through WARP"
            else
                print_warn "  ✗ Python connection test failed despite certificate being configured"
                has_issues=true
            fi
        else
            if [ -z "${REQUESTS_CA_BUNDLE:-}" ] && [ -z "${SSL_CERT_FILE:-}" ]; then
                print_warn "  ✗ No Python certificate environment variables configured"
                has_issues=true
            elif [ -z "${REQUESTS_CA_BUNDLE:-}" ]; then
                print_warn "  ✗ REQUESTS_CA_BUNDLE not configured"
                has_issues=true
            else
                # REQUESTS_CA_BUNDLE or SSL_CERT_FILE is set but doesn't contain the cert
                has_issues=true
            fi
        fi
    else
        print_info "  - Python not installed"
    fi
    echo
    
    # Check curl configuration
    print_status "curl Configuration:"
    if command_exists curl; then
        local verify_result=$(verify_connection "curl")
        if [ "$verify_result" = "WORKING" ]; then
            print_info "  ✓ curl can connect through WARP"
            # Check if it's using SecureTransport (macOS system curl)
            if curl --version 2>/dev/null | grep -q "SecureTransport"; then
                print_info "  ✓ Using macOS system curl with SecureTransport (uses system keychain)"
            elif [ -n "${CURL_CA_BUNDLE:-}" ]; then
                print_info "  ✓ CURL_CA_BUNDLE is set to: $CURL_CA_BUNDLE"
            fi
        else
            if [ -n "${CURL_CA_BUNDLE:-}" ]; then
                print_info "  ✓ CURL_CA_BUNDLE is set"
            else
                print_warn "  ✗ curl connection test failed and CURL_CA_BUNDLE not set"
                has_issues=true
            fi
        fi
    else
        print_info "  - curl not installed"
    fi
    echo
    
    # Check wget configuration
    print_status "wget Configuration:"
    if command_exists wget; then
        if [ -f "$HOME/.wgetrc" ] && grep -q "ca_certificate=" "$HOME/.wgetrc"; then
            local current_ca=$(grep "ca_certificate=" "$HOME/.wgetrc" | tail -1)
            if [[ "$current_ca" == *"$CERT_PATH"* ]]; then
                print_info "  ✓ wget configured with Cloudflare certificate"
                local verify_result=$(verify_connection "wget")
                if [ "$verify_result" = "WORKING" ]; then
                    print_info "  ✓ wget can connect through WARP"
                else
                    print_warn "  ✗ wget connection test failed"
                    has_issues=true
                fi
            else
                print_warn "  ✗ wget not configured with Cloudflare certificate"
                has_issues=true
            fi
        else
            print_warn "  ✗ wget not configured"
            has_issues=true
        fi
    else
        print_info "  - wget not installed"
    fi
    echo
    
    # Check Java configuration
    print_status "Java Configuration:"
    if command_exists java || command_exists keytool; then
        if command_exists keytool; then
            if keytool -list -alias cloudflare-zerotrust -cacerts -storepass changeit 2>/dev/null | grep -q cloudflare-zerotrust; then
                print_info "  ✓ Java keystore contains Cloudflare certificate"
            else
                print_warn "  ✗ Java keystore missing Cloudflare certificate"
                has_issues=true
            fi
        else
            print_warn "  ✗ keytool not found"
            has_issues=true
        fi
    else
        print_info "  - Java not installed (would configure if present)"
    fi
    echo
    
    # Check gcloud configuration
    print_status "gcloud Configuration:"
    if command_exists gcloud; then
        local gcloud_ca=$(gcloud config get-value core/custom_ca_certs_file 2>/dev/null || echo "")
        if [ -n "$gcloud_ca" ] && [ -f "$gcloud_ca" ]; then
            if certificate_exists_in_file "$temp_warp_cert" "$gcloud_ca"; then
                print_info "  ✓ gcloud configured with current WARP certificate"
            else
                print_warn "  ✗ gcloud CA file doesn't contain current WARP certificate"
                has_issues=true
            fi
        else
            print_warn "  ✗ gcloud not configured with custom CA"
            has_issues=true
        fi
    else
        print_info "  - gcloud not installed (would configure if present)"
    fi
    echo
    
    # Check DBeaver configuration
    print_status "DBeaver Configuration:"
    local dbeaver_app="/Applications/DBeaver.app"
    if [ -d "$dbeaver_app" ]; then
        local dbeaver_keytool="$dbeaver_app/Contents/Eclipse/jre/Contents/Home/bin/keytool"
        local dbeaver_cacerts="$dbeaver_app/Contents/Eclipse/jre/Contents/Home/lib/security/cacerts"
        if [ -f "$dbeaver_keytool" ] && [ -f "$dbeaver_cacerts" ]; then
            if "$dbeaver_keytool" -list -alias cloudflare-zerotrust -keystore "$dbeaver_cacerts" -storepass changeit 2>/dev/null | grep -q cloudflare-zerotrust; then
                print_info "  ✓ DBeaver keystore contains Cloudflare certificate"
            else
                print_warn "  ✗ DBeaver keystore missing Cloudflare certificate"
                has_issues=true
            fi
        else
            print_warn "  ✗ DBeaver JRE not found at expected location"
        fi
    else
        print_info "  - DBeaver not installed at /Applications/DBeaver.app"
    fi
    echo
    
    # Check Podman configuration
    print_status "Podman Configuration:"
    if command_exists podman; then
        if podman machine list 2>/dev/null | grep -q "Currently running"; then
            # Check if certificate exists in Podman VM
            if podman machine ssh "test -f /etc/pki/ca-trust/source/anchors/cloudflare-warp.pem" 2>/dev/null; then
                print_info "  ✓ Podman VM has Cloudflare certificate installed"
            else
                print_warn "  ✗ Podman VM missing Cloudflare certificate"
                has_issues=true
            fi
        else
            print_info "  - Podman installed but no machine is running"
            print_info "    Start a machine with: podman machine start"
        fi
    else
        print_info "  - Podman not installed (would configure VM if present)"
    fi
    echo
    
    # Check Rancher Desktop configuration
    print_status "Rancher Desktop Configuration:"
    if command_exists rdctl; then
        # Try to check if Rancher is running
        if rdctl version 2>/dev/null | grep -q "rdctl"; then
            # Check if certificate exists in Rancher VM
            if rdctl shell test -f /usr/local/share/ca-certificates/cloudflare-warp.pem 2>/dev/null; then
                print_info "  ✓ Rancher Desktop VM has Cloudflare certificate installed"
            else
                print_warn "  ✗ Rancher Desktop VM missing Cloudflare certificate"
                has_issues=true
            fi
        else
            print_info "  - Rancher Desktop installed but not running"
        fi
    else
        print_info "  - Rancher Desktop not installed (would configure if present)"
    fi
    echo
    
    # Check Docker configuration
    print_status "Docker Configuration:"
    if command_exists docker; then
        print_info "  - Docker detected"
        print_info "    Note: Docker daemon certificate configuration varies by platform"
        print_info "    You may need to add certificates to Docker images directly"
    else
        print_info "  - Docker not installed"
    fi
    echo
    
    # Check Android Emulator
    print_status "Android Emulator Configuration:"
    if command_exists adb && command_exists emulator; then
        local running_emulators=$(adb devices 2>/dev/null | grep -E "emulator-[0-9]+" | wc -l)
        if [ "$running_emulators" -gt 0 ]; then
            print_info "  - Android emulator detected (manual installation available)"
            print_info "    Run with --fix to see installation instructions"
        else
            print_info "  - Android SDK detected but no emulator running"
        fi
    else
        print_info "  - Android SDK not installed (would help configure if present)"
    fi
    echo
    
    # Show information about additional tools
    print_status "Additional Tools (not yet automated):"
    print_info "  - RubyGems/Bundler: May work with SSL_CERT_FILE environment variable"
    print_info "  - PHP/Composer: May need CURL_CA_BUNDLE and php.ini configuration"
    print_info "  - Git: May need 'git config --global http.sslCAInfo' setting"
    print_info "  - Firefox: Uses its own certificate store in profile"
    print_info "  - Other Homebrew tools: May need individual configuration"
    echo
    
    # Summary
    print_info "Summary:"
    print_info "========"
    if [ "$has_issues" = true ]; then
        print_warn "Some configurations need attention."
        print_action "Run './fuwarp.sh --fix' to fix the issues"
    else
        print_info "✓ All configured tools are properly set up for Cloudflare WARP"
    fi
    echo
    
    # Cleanup
    rm -f "$temp_warp_cert"
}

# Function to setup wget certificate
setup_wget_cert() {
    if ! command_exists wget; then
        return 0
    fi

    local wgetrc_path="$HOME/.wgetrc"
    local config_line="ca_certificate=$CERT_PATH"

    if [ -f "$wgetrc_path" ] && grep -q "ca_certificate=" "$wgetrc_path"; then
        local current_ca=$(grep "ca_certificate=" "$wgetrc_path" | tail -1)
        # Check if it's already set to our certificate
        if [[ "$current_ca" == *"$CERT_PATH"* ]]; then
            return 0
        fi
        
        print_info "Setting up wget certificate..."
        print_warn "wget ca_certificate is already set in $wgetrc_path"
        print_info "Current setting: $current_ca"
        
        if ! is_install_mode; then
            print_action "Would ask to update the ca_certificate in $wgetrc_path"
            print_action "Would set: $config_line"
        else
            read -p "Do you want to update it? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Comment out old entries
                sed -i.bak 's/^ca_certificate=/#&/' "$wgetrc_path"
                echo "$config_line" >> "$wgetrc_path"
                print_info "Updated wget configuration in $wgetrc_path"
            fi
        fi
    else
        print_info "Setting up wget certificate..."
        
        if ! is_install_mode; then
            print_action "Would add to $wgetrc_path: $config_line"
        else
            print_info "Adding configuration to $wgetrc_path"
            echo "$config_line" >> "$wgetrc_path"
            print_info "Added ca_certificate to wget configuration"
        fi
    fi
}

# Main function
main() {
    print_info "Cloudflare Certificate Installation Script"
    print_info "========================================="
    
    if is_debug_mode; then
        print_debug "Script version: $(date -r "$0" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'unknown')"
        print_debug "Running on: $(uname -a)"
        print_debug "Shell: $SHELL"
        print_debug "PATH: $PATH"
        print_debug "Home directory: $HOME"
        print_debug "Certificate path: $CERT_PATH"
        if ! is_install_mode; then
            print_debug "Status mode: Using fast certificate checks"
        else
            print_debug "Install mode: Using thorough certificate checks"
        fi
        echo
    fi
    
    if ! is_install_mode; then
        # In status mode, just check current status
        check_all_status
    else
        print_info "Running in FIX mode - changes will be made to your system"
        echo
        
        # Download and verify certificate
        if ! download_certificate; then
            print_error "Failed to download certificate. Exiting."
            exit 1
        fi
        
        # Setup for different environments
        setup_node_cert
        setup_python_cert
        setup_gcloud_cert
        setup_java_cert
        setup_dbeaver_cert
        setup_wget_cert
        setup_podman_cert
        setup_rancher_cert
        setup_android_emulator_cert
        
        # Final message
        echo
        print_info "Installation completed!"
        
        if [ "$SHELL_MODIFIED" = true ]; then
            print_warn "Shell configuration was modified."
            print_warn "Please reload your shell configuration:"
            
            local shell_type=$(detect_shell)
            local shell_config=$(get_shell_config "$shell_type")
            
            case "$shell_type" in
                bash)
                    print_info "  source $shell_config"
                    ;;
                zsh)
                    print_info "  source $shell_config"
                    ;;
                fish)
                    print_info "  source $shell_config"
                    ;;
                *)
                    print_info "  Please restart your shell"
                    ;;
            esac
        fi
    fi
    
    echo
    print_info "Certificate location: $CERT_PATH"
    print_info "For additional applications, please refer to the documentation."
}

# Run main function
main "$@"
