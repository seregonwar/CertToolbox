# CertToolbox

## Overview

`CertToolbox` is a powerful Python-based utility designed to streamline the management and modification of `.p12` and `.mobileprovision` files. With `CertToolbox`, you can easily update essential certificate and provisioning information, such as issuer name, expiration date, country, and organization, all within a user-friendly graphical interface.

## Key Features

- **Certificate Modification**: Effortlessly update `.p12` and `.mobileprovision` files with new details.
- **Information Extraction**: Retrieve and display comprehensive information from certificates and provisioning profiles.
- **Certificate Repair**: Automatically fix damaged certificates with built-in repair functionality.
- **User-Friendly Interface**: Enjoy a clean, intuitive interface powered by `tkinter` and `ttkbootstrap`.

## System Requirements

- **Python Version**: Python 3.x
- **Required Python Libraries**:
  - `biplist`
  - `cryptography`
  - `tkinter`
  - `ttkbootstrap`
  - `lxml`
  - `re`
  - `logging`

## Installation Guide

To get started with `CertToolbox`, follow these steps:

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/seregonwar/CertToolbox.git
    ```

2. **Install Dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

## How to Use

Follow these steps to utilize the main functionalities of `CertToolbox`:

### Running the Tool

1. **Launch the Script**:
    ```sh
    python CertToolBox.py
    ```

2. **Graphical Interface Usage**:
   - Load your `.p12` and `.mobileprovision` files.
   - Enter the updated information as required.

### Certificate Modification

1. **Select Files**: Choose the `.p12` and `.mobileprovision` files you wish to modify.
2. **Input Password**: Enter the current password associated with the `.p12` file.
3. **Update Information**: Provide the new issuer name, country, organization, and set the desired expiration period.
4. **Modify Certificate**: Click "Start Modification" to apply the changes.

### Information Extraction

1. **Select Files**: Choose the `.p12` and `.mobileprovision` files.
2. **Input Password**: Enter the current password for the `.p12` file.
3. **Extract Details**: Click "Verify Certificate" to view detailed information.

### Certificate Repair

1. **Select Files**: Load the `.p12` and `.mobileprovision` files requiring repair.
2. **Input Password**: Provide the password for the `.p12` file.
3. **Repair Certificate**: Click "Insert PEM Key" to initiate the repair process using a PEM key.

## Project Goals

- **Simplify Certificate Management**: Provide a straightforward interface to manage and update certificates.
- **Automate Processes**: Reduce manual effort and minimize errors through automated repair and modification processes.
- **Enhance Security**: Ensure that all modified certificates maintain high security and compliance standards.

## Contribution Guidelines

We welcome contributions from the community! If you'd like to contribute, please feel free to open issues or submit pull requests. Contributions can include bug fixes, feature enhancements, or documentation improvements.

## License

This project is licensed under the MIT License. For more details, please refer to the `LICENSE` file.

## Planned Enhancements

Looking forward, we aim to introduce the following improvements:

- **Extended Format Support**: Expand support to include additional certificate and provisioning file formats.
- **Enhanced Verification**: Introduce more rigorous verification checks to validate certificate integrity.
- **Expiration Alerts**: Implement notification features to alert users before certificate expiration.
- **Backup System**: Create an automatic backup system to safeguard original files prior to modification.
- **Comprehensive Documentation**: Offer more in-depth documentation and tutorials to enhance user experience.

## Contact Information

For inquiries or support, please reach out to the project maintainer at: `seregonwar@gmail.com`.

## GUI Preview

![CertToolbox Interface](https://github.com/user-attachments/assets/f01a90ea-9dd5-4a4b-9aaa-c44bdf7e647f)

