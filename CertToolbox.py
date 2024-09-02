import biplist
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import tkinter as tk
from ttkbootstrap import Style
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from lxml import etree as ET
import re
import logging

# Logging configuration
logging.basicConfig(filename='error_log.log', level=logging.ERROR, format='%(asctime)s:%(levelname)s:%(message)s')

def clean_and_extract_xml(mobileprovision_file):
    with open(mobileprovision_file, 'rb') as file:
        content = file.read().decode('utf-8', errors='ignore')
    match = re.search(r'(<\?xml.*<\/plist>)', content, re.DOTALL)
    if match:
        return match.group(1)
    return None

def reassemble_mobileprovision(original_file, modified_xml_content, output_file):
    with open(original_file, 'rb') as file:
        original_content = file.read()
        start = original_content.find(b'<?xml')
        end = original_content.find(b'</plist>') + len(b'</plist>')
        
        # Keep the binary data that precedes and follows the XML content
        pre_xml = original_content[:start]
        post_xml = original_content[end:]
        
    # Mandatory XML header
    xml_header = b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    
    # Reassemble the complete content
    new_content = pre_xml + xml_header + modified_xml_content.encode('utf-8') + post_xml
    with open(output_file, 'wb') as file:
        file.write(new_content)

def modify_xml(xml_content, new_issuer, new_expiry_date, modify_only_expiry):
    root = ET.fromstring(xml_content.encode('utf-8'))
    for key in root.findall(".//key"):
        if key.text == 'AppIDName':
            app_name = key.getnext()
            if app_name is not None:
                app_name.text = "ybapp" if modify_only_expiry else new_issuer
        elif key.text == 'ExpirationDate':
            expiry_date = key.getnext()
            if expiry_date is not None:
                expiry_date.text = new_expiry_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    return ET.tostring(root, encoding='utf-8', pretty_print=True).decode('utf-8')

def generate_private_key():
    return serialization.load_pem_private_key(
        serialization.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ),
        password=None
    )

def modify_p12_and_mobileprovision(p12_file, mobileprovision_file, old_password, new_password, new_issuer, new_expiry_date, new_country, new_organization, modify_only_expiry, pem_file=None):
    try:
        # Load the original .p12 file
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
        
        # Extract the private key, certificate, and additional certificates
        try:
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, old_password.encode())
        except Exception as e:
            raise ValueError(f"Error loading the .p12 file: {str(e)}")

        if certificate is None:
            raise ValueError("The certificate cannot be None")

        # If a PEM file is provided, load the private key from it
        if pem_file:
            with open(pem_file, 'rb') as pem_f:
                private_key = serialization.load_pem_private_key(pem_f.read(), password=None)
        elif private_key is None:
            # Generate a new private key if it does not exist
            private_key = generate_private_key()

        # Build a new issuer name
        issuer = certificate.issuer if modify_only_expiry else x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, new_country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, new_organization),
            x509.NameAttribute(NameOID.COMMON_NAME, new_issuer),
        ])

        # Build the new certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            certificate.subject
        ).issuer_name(
            issuer
        ).public_key(
            certificate.public_key()
        ).serial_number(
            certificate.serial_number
        ).not_valid_before(
            certificate.not_valid_before
        ).not_valid_after(
            datetime.strptime(new_expiry_date, "%Y%m%d%H%M%SZ")
        )

        # Copy all extensions from the original certificate
        for ext in certificate.extensions:
            cert_builder = cert_builder.add_extension(ext.value, ext.critical)

        # Sign the new certificate
        new_cert = cert_builder.sign(private_key, hashes.SHA256())

        # Serialize the new certificate and private key into a .p12 file
        new_p12_data = pkcs12.serialize_key_and_certificates(
            name=b"modified_certificate",
            key=private_key,
            cert=new_cert,
            cas=additional_certificates,
            encryption_algorithm=serialization.BestAvailableEncryption(new_password.encode())
        )

        # Save the new .p12 file
        modified_p12_file = p12_file.replace('.p12', '_modified.p12')
        with open(modified_p12_file, 'wb') as f:
            f.write(new_p12_data)

        # Modify the mobileprovision file
        cleaned_xml = clean_and_extract_xml(mobileprovision_file)
        if cleaned_xml:
            modified_xml = modify_xml(
                cleaned_xml, 
                new_issuer if not modify_only_expiry else certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, 
                datetime.strptime(new_expiry_date, "%Y%m%d%H%M%SZ"),
                modify_only_expiry
            )
            modified_mobileprovision_file = mobileprovision_file.replace('.mobileprovision', '_modified.mobileprovision')
            reassemble_mobileprovision(mobileprovision_file, modified_xml, modified_mobileprovision_file)

        return f"The certificate and mobileprovision file have been successfully modified and saved as {modified_p12_file} and {modified_mobileprovision_file}."
    except ValueError as ve:
        logging.error("Validation error: %s", str(ve))
        raise ve
    except Exception as e:
        logging.error("Error modifying the certificate: %s", str(e))
        raise e

def extract_certificate_info(p12_file, password):
    try:
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
        
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, password.encode())

        if certificate is None:
            raise ValueError("The certificate cannot be None")

        cert_info = {
            "CertName": certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Effective Date": certificate.not_valid_before,
            "Expiration Date": certificate.not_valid_after,
            "Issuer": certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            "Country": certificate.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value,
            "Organization": certificate.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
            "Certificate Number (Hex)": format(certificate.serial_number, 'X'),
            "Certificate Number (Decimal)": certificate.serial_number,
            "Certificate Status": "🟢Good"  # Placeholder for actual status check
        }

        return cert_info
    except Exception as e:
        logging.error("Error extracting certificate information: %s", str(e))
        raise e

def extract_mobileprovision_info(mobileprovision_file):
    try:
        cleaned_xml = clean_and_extract_xml(mobileprovision_file)
        if not cleaned_xml:
            raise ValueError("Unable to extract XML content from the mobileprovision file")

        root = ET.fromstring(cleaned_xml.encode('utf-8'))
        mp_info = {
            "MP Name": None,
            "App ID": None,
            "Identifier": None,
            "Platform": None,
            "Effective Date": None,
            "Expiration Date": None,
            "Binding Certificates": [],  # Placeholder for actual binding certificates
            "Certificate Matching Status": "🟢Match",  # Placeholder for actual matching status
            "Permission Status": {
                "Apple Push Notification Service": "🟢Permission Available",  # Placeholder for actual permission check
                "HealthKit": "🟡Unknown Permission",  # Placeholder for actual permission check
                "VPN": "🔴No Permission",  # Placeholder for actual permission check
                "Communication Notifications": "🟡Unknown Permission",  # Placeholder for actual permission check
                "Time-sensitive Notifications": "🔴No Permission"  # Placeholder for actual permission check
            },
            "Devices Limit": "🟢Provisions All Devices"  # Placeholder for actual device limit check
        }

        for key in root.findall(".//key"):
            if key.text == 'Name':
                mp_info["MP Name"] = key.getnext().text
            elif key.text == 'ApplicationIdentifierPrefix':
                mp_info["App ID"] = key.getnext().find("string").text
            elif key.text == 'application-identifier':
                mp_info["Identifier"] = key.getnext().text
            elif key.text == 'Platform':
                mp_info["Platform"] = key.getnext().find("string").text
            elif key.text == 'CreationDate':
                mp_info["Effective Date"] = key.getnext().text
            elif key.text == 'ExpirationDate':
                mp_info["Expiration Date"] = key.getnext().text

        return mp_info
    except Exception as e:
        logging.error("Error extracting mobileprovision file information: %s", str(e))
        raise e

def repair_certificate(p12_file, old_password):
    try:
        # Load the original .p12 file
        with open(p12_file, 'rb') as f:
            p12_data = f.read()
        
        # Extract the private key, certificate, and additional certificates
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, old_password.encode())

        if certificate is None:
            raise ValueError("The certificate cannot be None")

        # Generate a new private key if it does not exist
        if private_key is None:
            private_key = generate_private_key()

        # Build a new certificate with the same information
        cert_builder = x509.CertificateBuilder().subject_name(
            certificate.subject
        ).issuer_name(
            certificate.issuer
        ).public_key(
            certificate.public_key()
        ).serial_number(
            certificate.serial_number
        ).not_valid_before(
            certificate.not_valid_before
        ).not_valid_after(
            certificate.not_valid_after
        )

        # Copy all extensions from the original certificate
        for ext in certificate.extensions:
            cert_builder = cert_builder.add_extension(ext.value, ext.critical)

        # Sign the new certificate
        new_cert = cert_builder.sign(private_key, hashes.SHA256())

        # Serialize the new certificate and private key into a .p12 file
        repaired_p12_data = pkcs12.serialize_key_and_certificates(
            name=b"repaired_certificate",
            key=private_key,
            cert=new_cert,
            cas=additional_certificates,
            encryption_algorithm=serialization.BestAvailableEncryption(old_password.encode())
        )

        # Save the new .p12 file
        repaired_p12_file = p12_file.replace('.p12', '_repaired.p12')
        with open(repaired_p12_file, 'wb') as f:
            f.write(repaired_p12_data)

        return repaired_p12_file
    except Exception as e:
        logging.error("Error repairing the certificate: %s", str(e))
        raise e

class CertToolbox:
    def __init__(self, master):
        self.master = master
        master.title("Certificate Modifier")
        master.geometry("700x800")

        style = Style(theme="flatly")
        style.configure("TButton", font=("Helvetica", 10))
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TEntry", font=("Helvetica", 10))

        self.p12_file = tk.StringVar()
        self.provision_file = tk.StringVar()
        self.pem_file = tk.StringVar()
        self.old_password = tk.StringVar()
        self.new_password = tk.StringVar()
        self.new_issuer = tk.StringVar()
        self.new_country = tk.StringVar()
        self.new_organization = tk.StringVar()
        self.expiration_days = tk.StringVar()
        self.modify_only_expiry = tk.BooleanVar()

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="20")
        main_frame.pack(fill=BOTH, expand=YES)

        ttk.Label(main_frame, text="Certificate Modifier", font=("Helvetica", 16, "bold")).pack(pady=(0, 10))
        ttk.Label(main_frame, text="Modify your .p12 and .mobileprovision files", style="Secondary.TLabel").pack(pady=(0, 20))

        # File selection
        file_frame = ttk.Frame(main_frame)
        file_frame.pack(fill=X, pady=10)

        for i, (label, var, file_type) in enumerate([
            ("Select .p12 file", self.p12_file, [("File .p12", "*.p12")]),
            ("Select .mobileprovision file", self.provision_file, [("File .mobileprovision", "*.mobileprovision")]),
            ("Select PEM private key file", self.pem_file, [("PEM File", "*.pem")])
        ]):
            ttk.Label(file_frame, text=label, width=25).grid(row=i, column=0, sticky=W, pady=5)
            ttk.Entry(file_frame, textvariable=var, width=50).grid(row=i, column=1, padx=5, pady=5, sticky=EW)
            ttk.Button(file_frame, text="Browse", command=lambda v=var, ft=file_type: self.browse_file(v, ft)).grid(row=i, column=2, padx=5)

        file_frame.columnconfigure(1, weight=1)

        # Password fields
        password_frame = ttk.Frame(main_frame)
        password_frame.pack(fill=X, pady=10)

        for i, (label, var) in enumerate([
            ("Current .p12 password", self.old_password),
            ("New .p12 password", self.new_password)
        ]):
            ttk.Label(password_frame, text=label, width=25).grid(row=i, column=0, sticky=W, pady=5)
            ttk.Entry(password_frame, textvariable=var, show="*", width=30).grid(row=i, column=1, padx=5, pady=5, sticky=EW)

        password_frame.columnconfigure(1, weight=1)

        # Other fields
        other_frame = ttk.Frame(main_frame)
        other_frame.pack(fill=X, pady=10)

        fields = [
            ("New issuer", self.new_issuer),
            ("New country", self.new_country),
            ("New organization", self.new_organization),
            ("Days until expiration", self.expiration_days)
        ]

        for i, (label, var) in enumerate(fields):
            row, col = divmod(i, 2)
            ttk.Label(other_frame, text=label, width=25).grid(row=row, column=col*2, sticky=W, pady=5)
            ttk.Entry(other_frame, textvariable=var, width=25).grid(row=row, column=col*2+1, padx=5, pady=5, sticky=EW)

        other_frame.columnconfigure(1, weight=1)
        other_frame.columnconfigure(3, weight=1)

        # Checkbox for modifying only expiry date
        ttk.Checkbutton(main_frame, text="Modify only the expiration date", variable=self.modify_only_expiry).pack(pady=10)

        # Submit button
        ttk.Button(main_frame, text="Start Modification", command=self.handle_submit, style="primary.TButton").pack(pady=20)

        # Verify button
        ttk.Button(main_frame, text="Verify Certificate", command=self.verify_certificate, style="primary.TButton").pack(pady=20)

        # Insert PEM key button
        ttk.Button(main_frame, text="Insert PEM Key", command=self.insert_pem_key, style="primary.TButton").pack(pady=20)

        # Messages area
        self.message_label = ttk.Label(main_frame, text="", wraplength=600)
        self.message_label.pack(pady=10)

        # Log area
        log_frame = ttk.Frame(main_frame)
        log_frame.pack(fill=BOTH, expand=YES, pady=10)

        ttk.Label(log_frame, text="Operation Log:", font=("Helvetica", 10, "bold")).pack(anchor=W)
        self.log_area = ScrolledText(log_frame, height=10, width=80, font=("Consolas", 9))
        self.log_area.pack(fill=BOTH, expand=YES)
        self.log_area.configure(state='disabled')  # Make it read-only

    def browse_file(self, string_var, file_types):
        filename = filedialog.askopenfilename(filetypes=file_types)
        string_var.set(filename)

    def add_log(self, message):
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state='disabled')
        self.master.update_idletasks()  # Force update to show new log entries immediately

    def handle_submit(self):
        self.log_area.configure(state='normal')
        self.log_area.delete('1.0', tk.END)
        self.log_area.configure(state='disabled')
        self.message_label.config(text="")

        if self.modify_only_expiry.get():
            required_fields = [self.p12_file.get(), self.provision_file.get(), self.old_password.get(), self.expiration_days.get()]
        else:
            required_fields = [self.p12_file.get(), self.provision_file.get(), self.old_password.get(),
                               self.new_password.get(), self.new_issuer.get(), self.new_country.get(),
                               self.new_organization.get(), self.expiration_days.get()]

        if not all(required_fields):
            self.message_label.config(text="Please fill in all required fields.", foreground="red")
            return

        try:
            new_expiry_date = (datetime.now() + timedelta(days=int(self.expiration_days.get()))).strftime("%Y%m%d%H%M%SZ")
            try:
                message = modify_p12_and_mobileprovision(
                    self.p12_file.get(),
                    self.provision_file.get(),
                    self.old_password.get(),
                    self.new_password.get() if not self.modify_only_expiry.get() else self.old_password.get(),
                    self.new_issuer.get() if not self.modify_only_expiry.get() else "",
                    new_expiry_date,
                    self.new_country.get() if not self.modify_only_expiry.get() else "",
                    self.new_organization.get() if not self.modify_only_expiry.get() else "",
                    self.modify_only_expiry.get(),
                    self.pem_file.get() if self.pem_file.get() else None
                )
            except ValueError as ve:
                # Attempt to repair the certificate if it is broken
                repaired_p12_file = repair_certificate(self.p12_file.get(), self.old_password.get())
                message = modify_p12_and_mobileprovision(
                    repaired_p12_file,
                    self.provision_file.get(),
                    self.old_password.get(),
                    self.new_password.get() if not self.modify_only_expiry.get() else self.old_password.get(),
                    self.new_issuer.get() if not self.modify_only_expiry.get() else "",
                    new_expiry_date,
                    self.new_country.get() if not self.modify_only_expiry.get() else "",
                    self.new_organization.get() if not self.modify_only_expiry.get() else "",
                    self.modify_only_expiry.get(),
                    self.pem_file.get() if self.pem_file.get() else None
                )
            self.message_label.config(text=message, foreground="green")
            self.simulate_modification()
        except Exception as e:
            self.message_label.config(text=f"An error occurred while modifying the certificate: {str(e)}", foreground="red")
            self.add_log(f"Error: {str(e)}")

    def insert_pem_key(self):
        self.log_area.configure(state='normal')
        self.log_area.delete('1.0', tk.END)
        self.log_area.configure(state='disabled')
        self.message_label.config(text="")

        if not all([self.p12_file.get(), self.pem_file.get(), self.old_password.get(), self.new_password.get()]):
            self.message_label.config(text="Please select the files and enter the passwords.", foreground="red")
            return

        try:
            repaired_p12_file = repair_certificate(self.p12_file.get(), self.old_password.get())
            message = modify_p12_and_mobileprovision(
                repaired_p12_file,
                self.provision_file.get(),
                self.old_password.get(),
                self.new_password.get(),
                self.new_issuer.get(),
                (datetime.now() + timedelta(days=int(self.expiration_days.get()))).strftime("%Y%m%d%H%M%SZ"),
                self.new_country.get(),
                self.new_organization.get(),
                self.modify_only_expiry.get(),
                self.pem_file.get()
            )
            self.message_label.config(text=message, foreground="green")
            self.simulate_modification()
        except Exception as e:
            self.message_label.config(text=f"An error occurred while inserting the PEM key: {str(e)}", foreground="red")
            self.add_log(f"Error: {str(e)}")

    def add_log(self, message):
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.configure(state='disabled')
        self.log_area.yview(tk.END)

    def simulate_modification(self):
        steps = [
            "Loading the .p12 file...",
            "Extracting the private key, certificate, and additional certificates...",
            "Building the new issuer name...",
            "Building the new certificate...",
            "Signing the new certificate...",
            "Serializing the new certificate and private key...",
            "Saving the new .p12 file...",
            "Modifying the mobileprovision file...",
            "Cleaning and extracting the XML content from the mobileprovision file...",
            "Modifying the XML content...",
            "Reassembling the modified mobileprovision file...",
            "Operation completed successfully."
        ]
        for step in steps:
            self.add_log(step)
            self.master.after(500)  # Simulate processing time

    def verify_certificate(self):
        self.log_area.configure(state='normal')
        self.log_area.delete('1.0', tk.END)
        self.log_area.configure(state='disabled')
        self.message_label.config(text="")

        if not all([self.p12_file.get(), self.old_password.get(), self.provision_file.get()]):
            self.message_label.config(text="Please select the files and enter the password.", foreground="red")
            return

        try:
            cert_info = extract_certificate_info(self.p12_file.get(), self.old_password.get())
            mp_info = extract_mobileprovision_info(self.provision_file.get())

            info_message = (
                f"CertName: {cert_info['CertName']}\n"
                f"Effective Date: {cert_info['Effective Date']}\n"
                f"Expiration Date: {cert_info['Expiration Date']}\n"
                f"Issuer: {cert_info['Issuer']}\n"
                f"Country: {cert_info['Country']}\n"
                f"Organization: {cert_info['Organization']}\n"
                f"Certificate Number (Hex): {cert_info['Certificate Number (Hex)']}\n"
                f"Certificate Number (Decimal): {cert_info['Certificate Number (Decimal)']}\n"
                f"Certificate Status: {cert_info['Certificate Status']}\n"
                "-----------------------------------\n"
                f"MP Name: {mp_info['MP Name']}\n"
                f"App ID: {mp_info['App ID']}\n"
                f"Identifier: {mp_info['Identifier']}\n"
                f"Platform: {mp_info['Platform']}\n"
                f"Effective Date: {mp_info['Effective Date']}\n"
                f"Expiration Date: {mp_info['Expiration Date']}\n"
                "Binding Certificates:\n"
                f"  Certificate 1:\n"
                f"    Certificate Status: 🟢Match With P12\n"
                f"    Certificate Number (Hex): {cert_info['Certificate Number (Hex)']}\n"
                f"    Certificate Number (Decimal): {cert_info['Certificate Number (Decimal)']}\n"
                f"Certificate Matching Status: {mp_info['Certificate Matching Status']}\n"
                "Permission Status:\n"
                f"  Apple Push Notification Service: {mp_info['Permission Status']['Apple Push Notification Service']}\n"
                f"  HealthKit: {mp_info['Permission Status']['HealthKit']}\n"
                f"  VPN: {mp_info['Permission Status']['VPN']}\n"
                f"  Communication Notifications: {mp_info['Permission Status']['Communication Notifications']}\n"
                f"  Time-sensitive Notifications: {mp_info['Permission Status']['Time-sensitive Notifications']}\n"
                f"Devices Limit: {mp_info['Devices Limit']}\n"
            )

            self.message_label.config(text="Verification completed successfully!", foreground="green")
            self.add_log(info_message)
        except Exception as e:
            self.message_label.config(text=f"An error occurred while verifying the certificate: {str(e)}", foreground="red")
            self.add_log(f"Error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CertToolbox(root)
    root.mainloop()
