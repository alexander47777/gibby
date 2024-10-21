import requests
import re
import argparse
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Constants for GitHub API
GITHUB_API_URL = "https://api.github.com/search/code"
GITHUB_RATE_LIMIT_URL = "https://api.github.com/rate_limit"

# Hard-coded GitHub API Token
GITHUB_TOKEN = "YOUR-TOEKNS-HERE"

# Sensitive data patterns (predefined)

PATTERNS = {
    'API_KEY': r'api_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{20,}',  # Generic API key pattern
    'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    'PASSWORD': r'password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Generic password
    'NPMRC_AUTH': r'_auth\s*=\s*[A-Za-z0-9+/=]{40,}',  # NPM _auth tokens
    'DOCKERCFG': r'{"auths":\s*\{[^}]*"auth":\s*"[^"]*"}',  # Docker config auth block
    'PEM_PRIVATE_KEY': r'-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----[\s\S]+?-----END \1 KEY-----',  # Private key in PEM format
    'ID_RSA': r'-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----',  # id_rsa private key
    'AWS_ACCESS_KEY_ID': r'aws_access_key_id["\']?\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    'S3CFG': r's3cfg',  # Simple match for s3cfg files
    'HTPASSWD': r'\$apr1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}',  # Apache htpasswd hash
    'GIT_CREDENTIALS': r'url\s*=\s*https://.*:[A-Za-z0-9-_%]+@github.com',  # git-credentials file pattern
    'BASHRC_PASSWORD': r'password\s*=\s*[A-Za-z0-9-_!@#$%^&*]{8,}',  # Password found in .bashrc files
    'SSHD_CONFIG': r'(?i)(PermitRootLogin\s+yes|PasswordAuthentication\s+yes)',  # Insecure SSHD config options
    'SLACK_TOKEN': r'(xox[abp]-[A-Za-z0-9]{10,48})',  # Slack tokens (xoxp, xoxb, xoxa)
    'SECRET_KEY': r'secret_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Generic secret key
    'CLIENT_SECRET': r'client_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # OAuth Client Secret
    'GITHUB_TOKEN': r'ghp_[A-Za-z0-9]{36}',  # GitHub personal access token
    'FTP': r'ftp://[^:]+:(.+)@',  # FTP credentials in URL
    'APP_SECRET': r'app_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # App secret key
    'PASSWD_FILE': r'root:[x*]:0:0:',  # Linux passwd file root entry
    'S3_YML': r's3\.yml',  # S3 configuration YAML files
    'EXS_FILE': r'\.exs$',  # Elixir script files
    'BEANSTALKD_YML': r'beanstalkd\.yml',  # beanstalkd config files
    'DEPLOY_RAKE': r'deploy\.rake',  # Ruby deploy script
    'MYSQL': r'mysql["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # MySQL password
    'CREDENTIALS': r'credentials["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Generic credentials
    'PWD': r'PWD["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{8,}',  # PWD environment variable
    'BASH_HISTORY': r'.bash_history',  # Bash history file
    'SLS': r'\.sls$',  # SaltStack files
    'SECRETS': r'secrets["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Secrets file entry
    'COMPOSER_JSON': r'composer\.json',  # Composer JSON files
    'APP_ID': r'app_id["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{8,}',  # App ID
    'AUTH_TOKEN': r'auth_token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Authentication token
    'AUTH_KEY': r'auth_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Authentication key
    'AWS_SECRET': r'AWS_SECRET["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{40}',  # AWS Secret key
    'AWS_SECRET_KEY': r'aws_secret_access_key["\']?\s*[:=]\s*[A-Za-z0-9/+=]{40}',  # AWS secret key
    'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    'AUTH': r'auth["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # General auth key
    'AUTH0_CLIENT_ID': r'auth0_client_id["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{20,}',  # Auth0 Client ID
    'AUTH0_CLIENT_SECRET': r'auth0_client_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{40}',  # Auth0 Client Secret
    'CARGO_TOKEN': r'CARGO_TOKEN["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{20,}',  # Cargo registry token
    'CF_PASSWORD': r'CF_PASSWORD["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Cloud Foundry password
    'CI_USER_TOKEN': r'CI_USER_TOKEN["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # CI user token
    'DATABASE_PASSWORD': r'database_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Database password
    'DOCKER_HUB_PASSWORD': r'docker_hub_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Docker Hub password
    'ELASTICSEARCH_PASSWORD': r'elasticsearch_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Elasticsearch password
    'EMAIL': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',  # Generic email pattern
    'EXP_PASSWORD': r'exp_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Expo CLI password
    'FIREBASE_API_TOKEN': r'firebase_api_token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Firebase API token
    'FTP_LOGIN': r'ftp://[^:]+:(.+)@',  # FTP login credentials
    'FTP_PASSWORD': r'ftp_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # FTP password
    'GH_AUTH_TOKEN': r'ghp_[A-Za-z0-9]{36}',  # GitHub authentication token
    'ID_RSA_PUB': r'-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----',  # RSA public key
    'JWT_SECRET': r'jwt_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # JWT Secret
    'JDBC_USER': r'jdbc_user["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{8,}',  # JDBC user
    'MAILCHIMP_API_KEY': r'mailchimp_api_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Mailchimp API key
    'MANIFEST_APP_TOKEN': r'manifest_app_token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Manifest app token
    'MYSQL_PASSWORD': r'mysql_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # MySQL password
    'NETLIFY_API_KEY': r'netlify_api_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Netlify API key
    'NPM_API_TOKEN': r'npm_api_token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # NPM API token
    'OSSRH_JIRA_PASSWORD': r'ossrh_jira_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # OSSRH JIRA password
    'PASSWORD_TRAVIS': r'password_travis["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # Travis CI password
    'S3_ACCESS_KEY': r's3_access_key["\']?\s*[:=]\s*[A-Za-z0-9]{16,}',  # S3 access key
    'SENDGRID_KEY': r'sendgrid_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # SendGrid API key
    'SSMTP_CONFIG': r'ssmtpd\.conf',  # SSMTP configuration files
    'TRAVIS_SECURE_ENV_VARS': r'travis_secure_env_vars["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Travis CI secure env vars
    'TWILIO_TOKEN': r'twilio_token["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Twilio token
    'URBAN_MASTER_SECRET': r'urban_master_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # Urban Airship secret
    'VIP_GITHUB_DEPLOY_KEY': r'vip_github_deploy_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # VIP GitHub deploy key
    'WORDPRESS_DB_PASSWORD': r'wordpress_db_password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}',  # WordPress DB password
    'YT_CLIENT_SECRET': r'yt_client_secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{32,}',  # YouTube client secret
    'DB_USERNAME': r'db[_-]?username["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_]{3,}',  # Generic database username
    'DB_PASSWORD': r'db[_-]?password["\']?\s*[:=]\s*["\']?[A-Za-z0-9-_!@#$%^&*]{8,}'  # Generic database password
}



# Function to check GitHub API rate limits
def check_rate_limit():
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    response = requests.get(GITHUB_RATE_LIMIT_URL, headers=headers)
    
    if response.status_code == 200:
        rate_limit = response.json()['resources']['core']
        remaining = rate_limit['remaining']
        reset_time = rate_limit['reset']
        return remaining, reset_time
    else:
        print(f"{Fore.RED}Error checking rate limit: {response.status_code} {response.text}")
        return None, None

# Function to enforce rate limit with improved logging
def enforce_rate_limit():
    remaining, reset_time = check_rate_limit()
    if remaining is not None and reset_time is not None:
        if remaining == 0:
            wait_time = reset_time - time.time()  # Time to wait until rate limit reset
            if wait_time > 0:
                print(f"{Fore.YELLOW}Rate limit exceeded. Waiting for {wait_time:.2f} seconds until reset...")
                time.sleep(wait_time + 10)  # Add 10 seconds buffer after rate limit reset
        else:
            print(f"{Fore.GREEN}Rate limit check passed: {remaining} requests remaining.")
    else:
        print(f"{Fore.RED}Unable to retrieve rate limit information.")


# Function to search GitHub with pagination support
def search_github(domain, pattern_name, pattern):
    query = f'"{domain}" "{pattern_name}"'  # Combine domain and pattern name for search query
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    params = {'q': query, 'per_page': 100}  # Get 100 results per page (max allowed)

    results = []
    page = 1
    
    while True:
        enforce_rate_limit()  # Check rate limit before making the request
        params['page'] = page
        response = requests.get(GITHUB_API_URL, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()['items']
            results.extend(data)
            print(f"{Fore.GREEN}Fetched page {page}, {len(data)} results.")
            
            # Check for 'next' in the Link header for pagination
            if 'next' not in response.links:
                break  # No more pages
            page += 1
        else:
            print(f"{Fore.RED}Error {response.status_code}: {response.json()['message']}")
            break
    
    return results

# Function to retrieve file content
def get_file_content(url):
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    
    enforce_rate_limit()  # Check rate limit before making the request

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        content = response.json()['content']
        return b64decode(content).decode('utf-8')
    else:
        print(f"{Fore.RED}Error retrieving file {response.status_code}")
        return None

# Function to read domains from file
def read_file_lines(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Error reading file {file_path}: {str(e)}")
        return []

# Function to search for sensitive data in the file content using patterns
def search_for_patterns(file_content):
    found_patterns = {}

    for pattern_name, pattern in PATTERNS.items():
        matches = re.findall(pattern, file_content, re.DOTALL | re.IGNORECASE)
        if matches:
            found_patterns[pattern_name] = matches

    return found_patterns

# Main function for CLI

def read_file_lines(filename):
    # Placeholder function for reading file lines.
    # Replace this with your actual implementation.
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def main():
    parser = argparse.ArgumentParser(description='GitHub Leak Detection Tool')
    parser.add_argument('domain_file', type=str, help='File containing list of domains to search for')

    args = parser.parse_args()

    domains = read_file_lines(args.domain_file)

    bold = "\033[1m"
    yellow = "\033[33m"
    cyan = "\033[36m"
    red = "\033[31m"
    green = "\033[32m"
    reset = "\033[0m"

    banner = [
        f"",
        f"{yellow} $$$$$$\  $$$$$$\ $$$$$$$\  $$$$$$$\ $$\     $$\ $$\\ ",
        f"{yellow}$$  __$$\ \_$$  _|$$  __$$\ $$  __$$\\$$\   $$  |$$ |",
        f"{yellow}$$ /  \__|  $$ |  $$ |  $$ |$$ |  $$ |\$$\ $$  / $$ |",
        f"{yellow}$$ |$$$$\   $$ |  $$$$$$$\ |$$$$$$$\ | \$$$$  /  $$ |",
        f"{yellow}$$ |\_$$ |  $$ |  $$  __$$\ $$  __$$\   \$$  /   \__|",
        f"{yellow}$$ |  $$ |  $$ |  $$ |  $$ |$$ |  $$ |   $$ |        ",
        f"{yellow}\$$$$$$  |$$$$$$\ $$$$$$$  |$$$$$$$  |   $$ |    $$\\ ",
        f"{yellow} \______/ \______|\_______/ \_______/    \__|    \__|{reset}"
    ]

    footer = [
        f"{yellow}===============================================",
        f"{bold}{yellow}🔥💻 Gibby Token Hunter 🔍",
        f"{yellow}===============================================",
        f"{bold}{cyan}🔑🔍 Searching GitHub for leaked tokens! 🚀💻",
        f"{yellow}===============================================",
        f"{bold}{green}👨‍💻✨ Written by {red}brave__ 🦸‍♂️",
        f"{yellow}==============================================={reset}"
    ]

    # Print the banner and footer
    for line in banner:
        print(line)
    print()
    for line in footer:
        print(line)

    
    for domain in domains:
        for pattern_name, pattern in PATTERNS.items():
            print()
            print(f"\n{Fore.GREEN}🔍 =====================================================")
            print(f"\n{Fore.YELLOW}🔍 Searching for domain: 🚀🚀{domain} with pattern: 🔍🔍{pattern_name}")
            print(f"\n{Fore.GREEN}🔍 =====================================================")
            results = search_github(domain, pattern_name, pattern)

            # Use ThreadPoolExecutor to retrieve file contents concurrently
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(get_file_content, item['url']): item for item in results}

                for future in as_completed(future_to_url):
                    item = future_to_url[future]
                    try:
                        file_content = future.result()
                        if file_content:
                            found_patterns = search_for_patterns(file_content)
                            if found_patterns:
                                print(f"\n{Fore.CYAN}📄 File: {item['html_url']}")
                                for pattern_name, matches in found_patterns.items():
                                    print(f"   - 🗝️  {Fore.GREEN}Pattern '{pattern_name}' found:")
                                    for match in matches:
                                        print(f"     {Fore.YELLOW} {match}")
                    except Exception as e:
                        print(f"{Fore.RED}Error processing {item['html_url']}: {str(e)}")

    print(f"\n{Fore.GREEN}=============================================================")
    print(f"🎉 {Fore.YELLOW}Scan Completed!")
    print(f"{Fore.GREEN}=============================================================")

if __name__ == "__main__":
    main()
