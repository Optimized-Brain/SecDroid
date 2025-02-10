

---

# SecDroid - OWASP MASVS Static Analyzer for Android Apps

![SecDroid Logo](./assets/logo.png)

SecDroid is a comprehensive static analysis tool designed to assess the security of Android APKs. Built upon the [OWASP Mobile Application Security Verification Standard (MASVS)](https://mas.owasp.org/MASVS/), SecDroid automatically decompiles and inspects Android applications to detect vulnerabilities, insecure configurations, and misconfigurations that could lead to data leakage or unauthorized access.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line Options](#command-line-options)
  - [Examples](#examples)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Features

- **OWASP MASVS-Based Analysis:**  
  Performs security checks based on OWASP MASVS criteria across multiple areas:
  - **V1: Architecture, Design and Threat Modeling**
  - **V2: Data Storage and Privacy**
  - **V3: Cryptography**
  - **V4: Authentication and Session Management**
  - **V5: Network Communication**
  - **V6: Platform Interaction**
  - **V7: Code Quality and Build Settings**
  - **V8: Reverse Engineering Resilience**

- **APK Decompilation:**  
  Utilizes [d2j-dex2jar](https://github.com/pxb1988/dex2jar) and [jadx](https://github.com/skylot/jadx) to convert APKs into Java source code and resources for in-depth analysis.

- **Static Code Inspection:**  
  Scans decompiled source files and resource files for common security issues such as:
  - Hardcoded sensitive data (keys, passwords, tokens)
  - Insecure data storage practices (unencrypted databases, exposed shared preferences)
  - Inadequate network security (weak TLS, improper certificate pinning)
  - Misconfigured permissions and IPC vulnerabilities

- **Detailed Reporting:**  
  Provides console output with color-coded sections and, when enabled, generates log files and HTML reports with full details of the findings.

- **Batch Scanning:**  
  Supports scanning of both single APK files and entire directories containing multiple APKs.

- **Linux-Optimized:**  
  Designed to run on Linux environments (recommended: Kali Linux) for best performance and compatibility.

---

## Prerequisites

Before running SecDroid, ensure that your Linux system has the following utilities installed:

- **grep:** For text pattern searching  
- **jadx:** Android decompiler  
- **d2j-dex2jar:** Converts DEX files to JAR format  
- **Python 3.x:** The tool is written in Python  

For example, on Debian/Ubuntu, you can install grep and Python using:

```sh
sudo apt update && sudo apt install grep python3 -y
```

Additionally, you must install jadx and dex2jar (see [Installation](#installation)).

---

## Installation

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/yourusername/SecDroid.git
   cd SecDroid
   ```

2. **Install Required Tools:**

   - **jadx:**
     ```sh
     wget https://github.com/skylot/jadx/releases/latest/download/jadx.zip
     unzip jadx.zip -d jadx
     sudo mv jadx /opt/
     ```

   - **d2j-dex2jar:**
     ```sh
     wget https://github.com/pxb1988/dex2jar/releases/latest/download/dex-tools.zip
     unzip dex-tools.zip -d dex-tools
     sudo mv dex-tools /opt/
     ```

3. **Update Your PATH (if needed):**

   Add the following lines to your `~/.bashrc` or `~/.profile`:

   ```sh
   export PATH=$PATH:/opt/jadx/bin:/opt/dex-tools
   ```

   Then, source your profile:

   ```sh
   source ~/.bashrc
   ```

---

## Usage

SecDroid is executed from the command line. The general syntax is:

```sh
python3 SecDroid.py [options] <APK_FILE_OR_DIRECTORY>
```

### Command Line Options

- `-h` : Display help and usage instructions.
- `-p` : Analyze a single APK file.
- `-m` : Analyze multiple APK files located in a directory.
- `-l` : Enable logging (creates both a `.txt` log file and an HTML report).

### Examples

- **Single APK Analysis:**

  ```sh
  python3 SecDroid.py -p /path/to/android_app.apk
  ```

- **Single APK Analysis with Logging:**

  ```sh
  python3 SecDroid.py -p /path/to/android_app.apk -l
  ```

- **Batch Analysis of a Directory:**

  ```sh
  python3 SecDroid.py -m /path/to/apk_directory/
  ```

- **Batch Analysis with Logging:**

  ```sh
  python3 SecDroid.py -m /path/to/apk_directory/ -l
  ```

---

## How It Works

1. **Introduction & Environment Checks:**  
   SecDroid displays an introductory banner and verifies that it is running on a Linux system. It also checks for the presence of required utilities (grep, jadx, d2j-dex2jar).

2. **APK Validation & Metadata Extraction:**  
   The tool confirms that the provided file exists, is an APK, calculates its size, and computes MD5 and SHA256 hashes for integrity verification.

3. **Decompilation:**  
   Using `d2j-dex2jar` and `jadx`, SecDroid decompiles the APK to extract the Java source code and resources into a designated directory.

4. **Manifest Analysis:**  
   It parses the AndroidManifest.xml to extract vital information such as the package name, version, SDK levels, and security-related configurations.

5. **Static Code Analysis:**  
   SecDroid recursively scans the decompiled sources and resource files to hunt for potential security vulnerabilities based on OWASP MASVS criteria. This includes checks for insecure data storage, weak cryptography, improper logging, and more.

6. **Reporting:**  
   Findings are output to the console with color-coded messages for quick identification. When the logging option is enabled, detailed logs and an HTML report are generated.

---

## Contributing

Contributions are welcome! If you wish to report bugs, suggest enhancements, or submit pull requests, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes with clear and descriptive commit messages.
4. Push your branch and open a pull request.

Please ensure that your contributions follow the coding style and include appropriate documentation and testing.

---

## License

SecDroid is released under the **MIT License**. See the [LICENSE](LICENSE) file for further details.

---

## Contact

For questions, suggestions, or feedback, please contact:

- **Author:** Shoaib Attar
- **Email:** [shoaibattar3849@gmail.com](mailto:shoaibattar3849@gmail.com)

Feel free to open an issue on GitHub or reach out directly via email.

---

*SecDroid is a project of the CoE CNDS Lab and is developed with the aim of enhancing mobile application security testing and ensuring adherence to industry best practices as defined by OWASP MASVS.*
