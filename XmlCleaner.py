import re

def extract_and_clean_xml(input_path, output_path):
    # Leggi il contenuto del file
    with open(input_path, 'rb') as file:
        content = file.read().decode('utf-8', errors='ignore')
    
    # Estrai il contenuto XML usando espressioni regolari
    match = re.search(r'(<\?xml.*<\/plist>)', content, re.DOTALL)
    if match:
        xml_content = match.group(1)
        
        # Pulisci e formatta il XML
        try:
            import xml.dom.minidom
            xml_parsed = xml.dom.minidom.parseString(xml_content)
            pretty_xml_as_string = xml_parsed.toprettyxml()
            
            # Scrivi il XML pulito in un nuovo file
            with open(output_path, 'w') as output_file:
                output_file.write(pretty_xml_as_string)
                
            print("XML estratto e salvato con successo.")
        except Exception as e:
            print("Errore durante il parsing o la formattazione del XML:", e)
    else:
        print("Contenuto XML non trovato nel file.")

# Percorsi dei file
input_file_path = 'c:\\Users\\marco\\Desktop\\Sunshine Insurance Group Co., Ltd\\Sunshine Insurance Group Co., Ltd..mobileprovision'
output_file_path = 'c:\\Users\\marco\\Desktop\\Sunshine Insurance Group Co., Ltd\\cleaned.xml'

# Esegui la funzione
extract_and_clean_xml(input_file_path, output_file_path)
