# Network Scanner

## Project Overview
The Network Scanner is a tool designed for network discovery and security auditing. It allows users to scan networks to identify active devices, services, and potential vulnerabilities.

## Features
- Fast and efficient scanning of local and remote networks.
- Detection of open ports and services on detected devices.
- User-friendly command-line interface.
- Extensive configuration options for advanced users.
- Simple reporting features to log scan results.

## Installation
To install the Network Scanner, follow these steps:
1. Clone the repository using `git clone https://github.com/ADITYA-CoDE101/Network_Scanner.git`
2. Navigate to the project directory: `cd Network_Scanner`
3. Install the required dependencies using `pip install -r requirements.txt` (if Python is used).

## Usage
- To perform a quick scan, use the following command:
  ```bash
  python scanner.py --quick [target]
  ```
- For a detailed scan, include additional flags:
  ```bash
  python scanner.py --detailed [target] --ports
  ```

## Commands
- `--quick`: Scans for active devices quickly.
- `--detailed`: Performs a comprehensive scan of specified ports.
- `--report`: Generates a report of the scan results.

## Architecture
The Network Scanner utilizes a modular architecture consisting of:
- **Scanner Module**: Core logic for scanning operations.
- **Report Module**: Handles reporting of scan results.
- **UI Module**: Manages user interactions through the command line.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with clear messages.
4. Push your branch and submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.