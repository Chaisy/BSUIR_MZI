import customtkinter as ctk
from hashlib import sha1
from hmac import HMAC
from gost_file import compute_gost_hash
from sha_file import compute_sha1_hash


def calculate_hash():
    algorithm = algo_var.get()
    text = text_entry.get("1.0", "end-1c")
    key = key_entry.get("1.0", "end-1c") if algorithm == "SHA-1" else None

    if algorithm == "GOST":
        result = compute_gost_hash(text)
        expected_result = compute_gost_hash(text)
    elif algorithm == "SHA-1":
        result = compute_sha1_hash(text, key)
        expected_result = HMAC(key.encode(), msg=text.encode(), digestmod=sha1).hexdigest()
    else:
        result = "Unknown Algorithm"
        expected_result = None

    result_label.configure(text=f"Result: {result}")
    if expected_result:
        expected_label.configure(text=f"Expected result: {expected_result}")


def update_key_entry_state(*args):
    if algo_var.get() == "GOST":
        key_entry.configure(state='disabled')
    else:
        key_entry.configure(state='normal')


app = ctk.CTk()
app.title("Hash Calculator")
app.geometry("400x400")

algo_var = ctk.StringVar(value="GOST")
algo_var.trace("w", update_key_entry_state)

algo_label = ctk.CTkLabel(app, text="Select algorithm:")
algo_label.pack(pady=10)
algo_menu = ctk.CTkOptionMenu(app, variable=algo_var, values=["GOST", "SHA-1"])
algo_menu.pack()

text_label = ctk.CTkLabel(app, text="Enter text:")
text_label.pack(pady=10)
text_entry = ctk.CTkTextbox(app, height=80)
text_entry.pack()

key_label = ctk.CTkLabel(app, text="Enter key (SHA-1):")
key_label.pack(pady=10)
key_entry = ctk.CTkTextbox(app, height=40)
key_entry.pack()

hash_button = ctk.CTkButton(app, text="Calculate hash", command=calculate_hash)
hash_button.pack(pady=20)

result_label = ctk.CTkLabel(app, text="Result:")
result_label.pack(pady=20)

expected_label = ctk.CTkLabel(app, text="Expected result:")
expected_label.pack(pady=20)

update_key_entry_state()  # Initial state of the key entry

app.mainloop()
