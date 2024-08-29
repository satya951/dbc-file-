import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import cantools
import os
from ftplib import FTP_TLS
import re
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
import time
import json

# Global variables  
id_checkboxes = {}
priority_comboboxes = {}
loaded_db = None
dbc_file_name = None
priority_map = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}  # Define priority map here
selected_items = []  # Define selected_items as a global variable
manually_entered_data = {827, 101, 102}  # Example data

# AWS IoT Core endpoint, AWS IoT Core Thing name, and MQTT topic
host = "a1xvyu1lci6ieh-ats.iot.eu-west-3.amazonaws.com"
rootCAPath = "certs/ca_cert.crt" #CA certificate file path (in certs folder)
certificatePath = "certs/client_cert.crt" #Certificate file path (in certs folder)
privateKeyPath = "certs/client_key.key" #Private key file path (in certs folder)
topic_log_config = "bateau/log_config" #Topic used to inform VCU that the a new configuration file has been set in the FTP server

# Configure AWS IoT MQTT client
mqtt_client = AWSIoTMQTTClient("uniqueClientId")
mqtt_client.configureEndpoint(host, 8883)
mqtt_client.configureCredentials(rootCAPath, privateKeyPath, certificatePath) #Define the credentials


def load_dbc_file():
    old_data_ids_str = []
    old_data_ids = []
    old_data_priorities = []
    global loaded_db, dbc_file_name
    file_path = filedialog.askopenfilename(filetypes=[("DBC files", "*.dbc")]) # it will load dbc file automacally 
    if file_path:
        loaded_db = cantools.database.load_file(file_path)
        dbc_file_name = os.path.basename(file_path)
        #file_label.config(text="Loaded DBC file: " + dbc_file_name)
        old_data_ids_str, old_data_priorities = load_old_data_ids_and_priorities_from_output_file(file_path)
        old_data_ids = [int(hex_id, 16) for hex_id in old_data_ids_str] #Convert hex list of IDs to decimal
        clear_labels()
        display_data(old_data_ids, old_data_priorities)

def display_data(old_data_ids, old_data_priorities):
    priority_list = ["HIGH", "MEDIUM", "LOW"]
    clear_labels()

    if loaded_db:

        # Display labels and widgets
        name_label = tk.Label(root, text="Messages:")
        name_label.grid(row=1, column=0, sticky='w')
        for i, message in enumerate(loaded_db.messages):
            message_label = tk.Label(root, text=message.name)
            message_label.grid(row=i+2, column=0, sticky='w') # the width oif the message 

        # Display IDs
        id_label = tk.Label(root, text="IDs:")
        id_label.grid(row=1, column=1, sticky='w')
        for i, message in enumerate(loaded_db.messages):
            id_label = tk.Label(root, text=f"0x{message.frame_id:03X}")
            id_label.grid(row=i+2, column=1, sticky='w') # it will dispaly  the id coloum and undwer it we have all i hexadecimal.

        # Add Select column
        select_label = tk.Label(root, text="Select")
        select_label.grid(row=1, column=2, sticky='w') 

        # Display checkboxes with corresponding data from DBC file
        for i, message in enumerate(loaded_db.messages):
            frame_id = message.frame_id
            checkbox_var = tk.IntVar(value=frame_id in old_data_ids)  # Check if frame ID is in manually_entered_data
            checkbox = tk.Checkbutton(root, variable=checkbox_var)
            checkbox.grid(row=i+2, column=3, sticky='w')
            id_checkboxes[frame_id] = checkbox_var

            # Display combo boxes with priorities under "Priority"
            priority_label = ttk.Label(root, text="Priority:")
            priority_label.grid(row=1, column=4, pady=5, padx=5, sticky="w")
            combo_box_values = priority_list
            combo_box = ttk.Combobox(root, values=combo_box_values, state="readonly")
            combo_box.grid(row=i+2, column=4, pady=5, padx=5, sticky="w")

            #Check if message has been configured in DBC comment
            if(frame_id in old_data_ids) :
                combo_box.set(priority_list[old_data_priorities[old_data_ids.index(frame_id)]-1])  # Set priority based on NWT comments

            priority_comboboxes[frame_id] = combo_box

def clear_labels():
    for widget in root.winfo_children():
        if isinstance(widget, (tk.Label, tk.Checkbutton, ttk.Combobox)):
            widget.grid_forget()
def get_priority_from_nwt_comments(frame_id):
    if loaded_db.messages:
        for message in loaded_db.messages:
            if message.comment and message.comment.startswith("// NWT comment"): #  the code will work  based //nwt comment it will split the frame id and priority.
                nwt_comments = message.comment.split("\n")
                for comment in nwt_comments:
                    # Check if the comment matches the frame_id
                    if comment.startswith(f"// #{frame_id:03X},"): # it will update the priority any data found under the //nwt comment .
                        parts = comment.split(", ")
                    if len(parts) == 2:
                            priority = parts[1].strip()  # Extract the priority
                            return priority  # Return the priority if found, exit the loop
    return ""  # Return an empty string if priority is not found


def load_old_data_ids_and_priorities_from_output_file(output_file_path):
    ids = []
    priorities = []
    dbc_file_name = None
    try:
        with open(output_file_path, "r") as output_file:
            lines = output_file.readlines()
                    # Look for the line containing "// NWT comments"
            for i, line in enumerate(lines):
                if "// NWT comments" in line:
                    # Iterate through subsequent lines to find IDs and priorities
                    for subline in lines[i+1:]:
                        match = re.match(r'// #([0-9a-fA-Fx]+),\s*(\d+)', subline)
                        if match:
                            ids.append(match.group(1))
                            priorities.append(int(match.group(2)))
                        else:
                            # Break if the line does not match the pattern
                            break

    except FileNotFoundError:
        pass  # Ignore if the file doesn't exist
    return ids, priorities 

def get_priority_from_nwt_comments(frame_id):
    if loaded_db.messages:
        for message in loaded_db.messages:
            if message.comment and message.comment.startswith("// NWT comment"): #  the code will work  based //nwt comment it will split the frame id and priority.
                nwt_comments = message.comment.split("\n")
                for comment in nwt_comments:
                    # Check if the comment matches the frame_id
                    if comment.startswith(f"// #{frame_id:03X},"): # it will update the priority any data found under the //nwt comment .
                        parts = comment.split(", ")
                    if len(parts) == 2:
                            priority = parts[1].strip()  # Extract the priority
                            return priority  # Return the priority if found, exit the loop
    return ""  # Return an empty string if priority is not found

def generate():
    global selected_items
    selected_items = []

    for frame_id, checkbox_var in id_checkboxes.items():
        if checkbox_var.get() == 1:
            priority_label = priority_comboboxes[frame_id].get()
            priority_value = priority_map.get(priority_label, 0)
            frame_id_hex = f"#0x{frame_id:03X}"
            selected_items.append((frame_id_hex, priority_value)) 

    if selected_items:
        # Determine the output DBC file name based on the loaded DBC file or provide a default name
        output_dbc_file_name = "output_" + (dbc_file_name if dbc_file_name else "default.dbc")
        output_txt_file_name = "output.txt"

        # Write the modifications to the new DBC file
        with open(output_dbc_file_name, "w") as output_dbc_file:
            # Write the content of the loaded DBC file
            if loaded_db:
                output_dbc_file.write(loaded_db.as_dbc_string())

            # Write the modifications
            output_dbc_file.write("// NWT comments\n")
            for frame_id_hex, priority_value in selected_items:
                output_dbc_file.write(f"// {frame_id_hex}, {priority_value}\n")   # the code will upadte any data in dbc file . 
    
        # Write output to the text file
        file_path = "output.txt"
        with open(file_path, "w") as file:
            file.write(f"DBC File: {dbc_file_name}\n")  # Write DBC file name to output file
            for frame_id_hex, priority_value in selected_items:
                file.write(f"{frame_id_hex}, {priority_value}\n") #  after selecting the data when we clikc on generate it will show output in .txt file 

        # Print output to console
        print("")
        for frame_id_hex, priority_value in selected_items:
            print(f"{frame_id_hex}, {priority_value}") # after selecting the data when we clikc on generate it will show output in console 

        # Notify the user about the completion
        messagebox.showinfo("Output Generated", f"Output written to {output_dbc_file_name} and {output_txt_file_name} successfully.")

def send_to_ftp():
    try:
        # Generate output file
        selected_items = []
        for frame_id, checkbox_var in id_checkboxes.items():
            if checkbox_var.get() == 1:
                priority_label = priority_comboboxes[frame_id].get()
                priority = priority_map[priority_label]
                # Format frame ID as desired
                frame_id_hex = f"#{frame_id:03X}"
                selected_items.append((frame_id, priority))

        if selected_items:
            file_path = "output.txt"
            with open(file_path, "w") as file:
                if dbc_file_name:
                    file.write(f"DBC File: {dbc_file_name}\n")  # Write DBC file name to output file
                for frame_id, priority in selected_items:
                    file.write(f"#0x{frame_id:x}, {priority}\n")  # Write ID in hexadecimal format

            # Connect to FTP server
            ftp_host = 'ftp.online.net'
            ftp_port = 21
            ftp_username = 'vcu@nwtechnology.fr'
            ftp_password = 'NWT_2024'
            ftp = FTP_TLS()
            ftp.connect(ftp_host, ftp_port)
            ftp.login(ftp_username, ftp_password)
            ftp.prot_p()

            # Send output file to FTP
            with open(file_path, "rb") as file:
                ftp.storbinary(f"STOR {file_path}", file)

            # Close FTP connection
            ftp.quit()

            #Once file has been transfered to FTP server, connect to MQTT and publish message to inform VCU

            # Connect to AWS IoT Core
            mqtt_client.connect()

            # Publish a sample message
            message = {"message": "New log configuration has been set in FTP server!"}
            mqtt_client.publish(topic_log_config, json.dumps(message), 1)

            # Wait for message to be delivered
            time.sleep(2)

            # Disconnect MQTT client
            mqtt_client.disconnect()

            # Notify the user that the file has been sent and the MQTT message has been published
            messagebox.showinfo("FTP - MQTT", f"File transfered to FTP server and MQTT message published !")

    except Exception as e:
        # Handle any exceptions that occur during FTP connection
        print("Error:", e)

root = tk.Tk()
root.title("DBC NWT Data Viewer")

file_label = ttk.Label(root, text="")
file_label.grid(row=0, column=0, columnspan=5, pady=5, padx=5, sticky="w")

load_button = ttk.Button(root, text="Load DBC File", command=load_dbc_file)
load_button.grid(row=0, column=1, pady=5, padx=5, sticky="w")

generate_button = ttk.Button(root, text="Generate", command=generate)
generate_button.grid(row=0, column=4, pady=5, padx=5, sticky="w")

send_to_ftp_button = ttk.Button(root, text="Send to FTP", command=send_to_ftp)
send_to_ftp_button.grid(row=0, column=5, pady=5, padx=5, sticky="w")

id_checkboxes = {}
priority_comboboxes = {}

root.mainloop()
