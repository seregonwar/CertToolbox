# CertToolbox

## Description
`CertToolbox` is an advanced Python tool for managing and modifying `.p12` and `.mobileprovision` files. This script allows you to update certificates and provisioning information, including issuer name, expiration date, country, and organization, through an intuitive graphical interface.

## Features
- **Certificate Modification**: Modify `.p12` and `.mobileprovision` files with new information.
- **Information Extraction**: Extract detailed information from the certificate and provisioning file.
- **Certificate Repair**: Automatically repair damaged certificates.
- **Graphical Interface**: Simple and intuitive user interface based on `tkinter` and `ttkbootstrap`.

## Requirements
- Python 3.x
- Python Modules:
  - `biplist`
  - `cryptography`
  - `tkinter`
  - `ttkbootstrap`
  - `lxml`
  - `re`
  - `logging`

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/CertToolbox.git
    ```
2. Install the requirements:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
1. Run the script:
    ```sh
    python CertCustomModifier.py
    ```
2. Use the graphical interface to select the `.p12` and `.mobileprovision` files and enter the new information.

## How It Works
### Certificate Modification
1. Select the `.p12` file and the `.mobileprovision` file.
2. Enter the current password for the `.p12` file.
3. Enter the new information (issuer name, country, organization, days until expiration).
4. Click "Start Modification" to begin the modification.

### Information Extraction
1. Select the `.p12` file and the `.mobileprovision` file.
2. Enter the current password for the `.p12` file.
3. Click "Verify Certificate" to extract and display the information.

### Certificate Repair
1. Select the `.p12` file and the `.mobileprovision` file.
2. Enter the current password for the `.p12` file.
3. Click "Insert PEM Key" to repair the certificate using a PEM key.

## Goals
- **Facilitate Certificate Management**: Provide a simple interface to modify and update certificates.
- **Automate Operations**: Automate the repair and modification of certificates to reduce manual errors.
- **Ensure Security**: Ensure that modified certificates are secure and compliant with standards.

## Contributions
Contributions are welcome! Feel free to open issues or pull requests.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Future Improvements
- **Support for Other Formats**: Add support for other certificate and provisioning file formats.
- **Advanced Verification**: Implement advanced verification checks to ensure the integrity and validity of certificates.
- **Notifications**: Add notifications to alert the user of impending certificate expiration.
- **Automatic Backup**: Implement an automatic backup system for original files before making modifications.
- **Extended Documentation**: Provide more detailed documentation and tutorials to facilitate the use of the tool.

## Contact
For any questions or support, you can contact the project maintainer at: seregonwar@gmail.com.
