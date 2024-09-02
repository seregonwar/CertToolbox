import biplist
import json
import tkinter as tk
from tkinter import filedialog
import xml.etree.ElementTree as ET
import plistlib

def convert_mobileprovision_to_json(input_file, output_file):
    try:
        # Carica il file .mobileprovision come plist
        data = biplist.readPlist(input_file)
        
        # Converti i dati in JSON
        with open(output_file, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        
        print("Conversione completata con successo.")
    except (biplist.InvalidPlistException, biplist.NotBinaryPlistException, FileNotFoundError) as e:
        print("Errore durante la conversione del file: Invalid file")

def modify_xml(input_file, output_file):
    # Carica il file XML
    tree = ET.parse(input_file)
    root = tree.getroot()
    
    # Modifica il valore di un elemento specifico
    # Ad esempio, cambiamo il nome dell'applicazione
    for elem in root.findall(".//dict/key"):
        if elem.text == "AppIDName":
            value = elem.getnext()
            value.text = "NuovoNomeApp"
            break
    
    # Salva il file XML modificato
    tree.write(output_file)

def modify_mobileprovision(input_file, output_file):
    # Apri il file .mobileprovision in modalità binaria
    with open(input_file, 'rb') as f:
        # Carica il file come plist
        plist_data = plistlib.load(f)

    # Modifica il plist come necessario
    # Ad esempio, cambiamo il nome dell'applicazione
    if 'AppIDName' in plist_data:
        plist_data['AppIDName'] = 'NuovoNomeApp'

    # Salva le modifiche nel file .mobileprovision
    with open(output_file, 'wb') as f:
        plistlib.dump(plist_data, f)

# Crea una finestra Tkinter nascosta
root = tk.Tk()
root.withdraw()

# Apri il file explorer per selezionare il file .mobileprovision
input_file = filedialog.askopenfilename(title="Seleziona il file .mobileprovision", filetypes=[("Mobile Provisioning Files", "*.mobileprovision")])
if not input_file:
    print("Nessun file selezionato. Uscita.")
    exit()

# Apri il file explorer per selezionare la destinazione del file JSON
output_file = filedialog.asksaveasfilename(title="Salva il file JSON come", defaultextension=".json", filetypes=[("JSON Files", "*.json")])
if not output_file:
    print("Nessun file di destinazione selezionato. Uscita.")
    exit()

convert_mobileprovision_to_json(input_file, output_file)
