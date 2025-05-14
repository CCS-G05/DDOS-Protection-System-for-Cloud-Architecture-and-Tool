import boto3
import tkinter as tk
from tkinter import messagebox, scrolledtext
import os
import json
from cryptography.fernet import Fernet
import threading
from PIL import Image, ImageTk

# ---------- Config & Utilities ----------
def get_script_location():
    return os.path.dirname(os.path.abspath(__file__))

def generate_key():
    return Fernet.generate_key()

def encrypt_credentials(credentials, key):
    f = Fernet(key)
    return f.encrypt(json.dumps(credentials).encode())

def decrypt_credentials(encrypted_data, key):
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted_data).decode())

def validate_aws_credentials(aws_access_key, aws_secret_key, aws_region):
    try:
        client = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
        client.describe_regions()
        return True
    except Exception:
        return False

# Global EC2 client
ec2 = None

# ---------- Network ACL Logic ----------
def get_existing_rules(nacl_id):
    nacls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = nacls['NetworkAcls'][0]['Entries']
    inbound = [e for e in entries if not e['Egress']]
    outbound = [e for e in entries if e['Egress']]
    return inbound, outbound

def rule_exists_for_ip(rules, cidr, action, egress):
    return any(
        r['CidrBlock'] == cidr and r['RuleAction'] == action and r['Egress'] == egress
        for r in rules
    )

def find_available_rule_number(entries, preferred):
    used = {entry['RuleNumber'] for entry in entries}
    if preferred not in used:
        return preferred
    for num in range(1, 32766):
        if num not in used:
            return num
    raise RuntimeError("No available rule numbers")

def block_ip_with_nacl(nacl_id, block_ip, output_box):
    try:
        cidr = f"{block_ip}/32"
        inbound, outbound = get_existing_rules(nacl_id)
        in_num = find_available_rule_number(inbound, 90)
        out_num = find_available_rule_number(outbound, 90)

        if not rule_exists_for_ip(inbound, cidr, 'deny', False):
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=in_num,
                Protocol='-1',
                RuleAction='deny',
                Egress=False,
                CidrBlock=cidr,
                PortRange={'From': 0, 'To': 65535}
            )
            output_box.insert(tk.END, f"Added inbound deny rule for {cidr}\n")
        else:
            output_box.insert(tk.END, f"Inbound deny rule for {cidr} already exists\n")

        if not rule_exists_for_ip(outbound, cidr, 'deny', True):
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=out_num,
                Protocol='-1',
                RuleAction='deny',
                Egress=True,
                CidrBlock=cidr,
                PortRange={'From': 0, 'To': 65535}
            )
            output_box.insert(tk.END, f"Added outbound deny rule for {cidr}\n")
        else:
            output_box.insert(tk.END, f"Outbound deny rule for {cidr} already exists\n")

        output_box.insert(tk.END, f"\nFinished blocking {cidr} via NACL {nacl_id}\n")
    except Exception as e:
        output_box.insert(tk.END, f"Error: {e}\n")

def remove_ip_from_nacl(nacl_id, block_ip, output_box):
    try:
        cidr = f"{block_ip}/32"
        inbound_rules, outbound_rules = get_existing_rules(nacl_id)
        removed = False

        for rule in inbound_rules:
            if rule['CidrBlock'] == cidr and rule['RuleAction'] == 'deny' and not rule['Egress']:
                ec2.delete_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule['RuleNumber'],
                    Egress=False
                )
                output_box.insert(tk.END, f"Removed inbound deny rule for {cidr} (#{rule['RuleNumber']})\n")
                removed = True

        for rule in outbound_rules:
            if rule['CidrBlock'] == cidr and rule['RuleAction'] == 'deny' and rule['Egress']:
                ec2.delete_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule['RuleNumber'],
                    Egress=True
                )
                output_box.insert(tk.END, f"Removed outbound deny rule for {cidr} (#{rule['RuleNumber']})\n")
                removed = True

        if not removed:
            output_box.insert(tk.END, f"\nNo DENY rules found for {cidr} in NACL {nacl_id}\n")

        output_box.insert(tk.END, f"\nFinished removing {cidr} from NACL {nacl_id}\n")
    except Exception as e:
        output_box.insert(tk.END, f"Error: {e}\n")

# ---------- GUI: AWS Credentials ----------
def aws_credentials_window():
    window = tk.Tk()
    window.title("AWS Credentials")
    window.geometry("550x255")
    
    ## window.config(padx=10)
    
    tk.Label(window, text="AWS Access Key").pack(pady=(10, 0))
    access_entry = tk.Entry(window, width=30)
    access_entry.pack(pady=5)

    tk.Label(window, text="AWS Secret Key").pack()
    secret_entry = tk.Entry(window, show="*", width=30)
    secret_entry.pack(pady=5)

    tk.Label(window, text="AWS Region").pack()
    region_entry = tk.Entry(window)
    region_entry.pack(pady=5)

    def on_validate():
        access_key = access_entry.get()
        secret_key = secret_entry.get()
        region = region_entry.get()

        def task():
            global ec2
            if validate_aws_credentials(access_key, secret_key, region):
                key = generate_key()
                creds = {
                    'AWS_ACCESS_KEY': access_key,
                    'AWS_SECRET_KEY': secret_key,
                    'AWS_REGION': region
                }
                enc = encrypt_credentials(creds, key)
                path = os.path.join(get_script_location(), "aws_credentials.dat")
                with open(path, "wb") as f:
                    f.write(enc + b"\n" + key)

                ec2 = boto3.client(
                    'ec2',
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
                window.after(0, lambda: [window.destroy(), choose_action_window()])
            else:
                window.after(0, lambda: messagebox.showerror("Error", "Invalid AWS credentials"))

        threading.Thread(target=task).start()

    tk.Button(window, text="Validate and Proceed", command=on_validate).pack(pady=10)

    # Add Authors' Information with enhanced style
    authors_label = tk.Label(window,
                             text="Authors: A Yuvaraja, Ashish S, Chitragar Rajesh, Siddharth Bej, Venkat Deepak J",
                             font=("Helvetica", 10, "bold"),
                             fg="white",
                             bg="#4CAF50",
                             relief="solid",
                             padx=10, pady=5)
    authors_label.pack(side='bottom', fill='x', pady=5)

    window.mainloop()


# ---------- GUI: Choose Action ----------
def choose_action_window():
    win = tk.Tk()
    win.title("Choose Action")
    win.geometry("300x355")

    # Load and display image
    try:
        img_path = os.path.join(get_script_location(), "./1.jpg")  # Update with your actual image file
        img = Image.open(img_path)
        img = img.resize((200, 200))  # Resize image to fit the window nicely
        img_tk = ImageTk.PhotoImage(img)

        img_label = tk.Label(win, image=img_tk)
        img_label.image = img_tk  # Keep a reference to avoid garbage collection
        img_label.pack(pady=5)
    except Exception as e:
        print(f"Failed to load image: {e}")

    tk.Label(win, text="What do you want to do?").pack(pady=10)

    tk.Button(win, text="Block an IP", command=lambda: [win.destroy(), block_ip_window()]).pack(pady=5)
    tk.Button(win, text="Remove an IP", command=lambda: [win.destroy(), remove_ip_window()]).pack(pady=5)

    win.mainloop()

# ---------- GUI: Block IP ----------
def block_ip_window():
    window = tk.Tk()
    window.title("Block IP")
    window.geometry("480x420")
    window.resizable(True, True)  # Allow resizing the window

    tk.Label(window, text="NACL ID").pack(pady=(10, 5))
    nacl_entry = tk.Entry(window, width=30)
    nacl_entry.pack()

    tk.Label(window, text="IP to block (without CIDR)").pack(pady=5)
    ip_entry = tk.Entry(window)
    ip_entry.pack()

    output_box = scrolledtext.ScrolledText(window, height=10, width=50)
    output_box.pack(pady=10)

    def on_block():
        nacl_id = nacl_entry.get()
        ip = ip_entry.get()
        output_box.insert(tk.END, f"Blocking {ip} in {nacl_id}...\n")

        def task():
            block_ip_with_nacl(nacl_id, ip, output_box)

        threading.Thread(target=task).start()

    def clear_logs():
        output_box.delete(1.0, tk.END)

    def go_back():
        window.destroy()
        choose_action_window()

    tk.Button(window, text="Clear Logs", command=clear_logs).pack(pady=5)
    tk.Button(window, text="Back", command=go_back).pack(pady=5)
    tk.Button(window, text="Block IP", command=on_block).pack(pady=5)
    window.mainloop()

# ---------- GUI: Remove IP ----------
def remove_ip_window():
    window = tk.Tk()
    window.title("Remove IP")
    window.geometry("480x420")
    window.resizable(True, True)  # Allow resizing the window

    tk.Label(window, text="NACL ID").pack(pady=(10, 5))
    nacl_entry = tk.Entry(window, width=30)
    nacl_entry.pack()

    tk.Label(window, text="IP to remove (without CIDR)").pack(pady=5)
    ip_entry = tk.Entry(window)
    ip_entry.pack()

    output_box = scrolledtext.ScrolledText(window, height=10, width=50)
    output_box.pack(pady=10)

    def on_remove():
        nacl_id = nacl_entry.get()
        ip = ip_entry.get()
        output_box.insert(tk.END, f"Removing {ip} from {nacl_id}...\n")

        def task():
            remove_ip_from_nacl(nacl_id, ip, output_box)

        threading.Thread(target=task).start()

    def clear_logs():
        output_box.delete(1.0, tk.END)

    def go_back():
        window.destroy()
        choose_action_window()

    tk.Button(window, text="Clear Logs", command=clear_logs).pack(pady=5)
    tk.Button(window, text="Back", command=go_back).pack(pady=5)
    tk.Button(window, text="Remove IP", command=on_remove).pack(pady=5)
    window.mainloop()

# ---------- Load Saved Credentials ----------
def load_aws_credentials():
    try:
        path = os.path.join(get_script_location(), "aws_credentials.dat")
        with open(path, "rb") as f:
            parts = f.read().split(b"\n")
            if len(parts) != 2:
                raise ValueError("Corrupt credentials file")
            enc, key = parts
            return decrypt_credentials(enc, key)
    except Exception as e:
        print(f"[Error loading credentials] {e}")
        return None

# ---------- Main ----------
if __name__ == "__main__":
    creds = None
    if os.path.exists(os.path.join(get_script_location(), "aws_credentials.dat")):
        creds = load_aws_credentials()

    if creds and validate_aws_credentials(creds['AWS_ACCESS_KEY'], creds['AWS_SECRET_KEY'], creds['AWS_REGION']):
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=creds['AWS_ACCESS_KEY'],
            aws_secret_access_key=creds['AWS_SECRET_KEY'],
            region_name=creds['AWS_REGION']
        )
        choose_action_window()
    else:
        aws_credentials_window()