# 🔍 GitHub Leak Detection Tool

This tool helps identify potential security leaks in publicly available GitHub repositories by searching for specific **domains** and **keywords** in code. It uses the GitHub Search API to scan repositories and locate sensitive data such as passwords, API keys, and configuration files.

## 🛠 Features

- **Domain-Based Search**: Input a list of domains to scan across GitHub repositories.
- **Custom Keyword Search**: Provide a list of keywords to search within the repositories.
- **Concurrent Processing**: Utilizes multi-threading to scan multiple files simultaneously, improving speed and efficiency.
- **GitHub API Integration**: Searches are performed using the GitHub Code Search API.
- **Rate Limiting Handling**: Automatically respects GitHub’s API rate limits by pausing and resuming the search when necessary.
- **Outputs Matching Content**: Displays the files and the actual content that matches your search criteria, such as exposed API keys, passwords, and other sensitive data.
  
## 📝 Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/alexander47777/gibby.git