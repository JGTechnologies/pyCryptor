import base64
import os
import rsa
import tkinter as tk

from tkinter import filedialog
from tkinter import messagebox

class MainApplication(tk.Frame):
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        self.master = master
        self.configure_gui()
        self.create_widgets()

        self.public_key_file = "public_key.pem"
        self.private_key_file = "private_key.pem"
        self.saved_keys_file = "saved_keys.csv"

        if not os.path.exists(self.public_key_file):
            self.generate_keys(2048)

        if not os.path.exists(self.saved_keys_file):
            with open(self.saved_keys_file, "w+") as hFile:
                # do nothing, just create an empty file for later
                pass

    def clear_target_path(self):
        self.target_path.delete(0, tk.END)

    def configure_gui(self):
        self.master.title("Encryptor")
        self.master.geometry("400x150")
        self.master.resizable(False, False)

        self.grid(padx = 50, pady = 20)
        self.master.columnconfigure((0, 2), weight = 1)
        self.master.columnconfigure(1, weight = 3)
        self.master.rowconfigure((0, 1, 2, 3, 4), weight = 1)

    def create_widgets(self):
        # first define the widgets then layout is specified below
        # defines the path and the browse button
        self.target_path_label = tk.Label(self.master, text = "Target Path: ")
        self.target_path = tk.Entry(self.master, borderwidth = 2)
        self.target_path_ofd_button = tk.Button(self.master, text = "...", command = self.show_browse_dialog)

        # allows changing the type from file <-> directory (recursive)
        self.target_type = tk.BooleanVar()

        self.target_type_frame = tk.Frame(self.master)

        self.target_type_label = tk.Label(self.master, text = "Type: ")
        self.target_type_file_radio = tk.Radiobutton(self.target_type_frame, text = "File", variable = self.target_type, value = 0, command = self.clear_target_path)
        self.target_type_dir_radio = tk.Radiobutton(self.target_type_frame, text = "Directory", variable = self.target_type, value = 1, command = self.clear_target_path)

        # choose whether to encrypt or decrypt
        self.direction_frame = tk.Frame(self.master)

        self.direction = tk.BooleanVar()
        self.direction_label = tk.Label(self.master, text = "Direction: ")
        self.direction_encrypt_radio = tk.Radiobutton(self.direction_frame, text = "Encrypt", variable = self.direction, value = 0, command = self.show_encryption_keys)
        self.direction_decrypt_radio = tk.Radiobutton(self.direction_frame, text = "Decrypt", variable = self.direction, value = 1, command = self.show_decryption_keys)

        # keys
        self.selected_key = tk.StringVar()
        available_keys = [ "My Private Key" ]
        self.selected_key.set(available_keys[0])

        self.target_key_label = tk.Label(self.master, text = "Key: ")
        self.key_options = tk.OptionMenu(self.master, self.selected_key, *available_keys)
        self.view_key_management_button = tk.Button(self.master, text = "Keys", command = self.show_key_management_window)

        # grid layout
        # path info
        self.target_path_label.grid(row = 0, column = 0)
        self.target_path.grid(row = 0, column = 1, sticky = "EW")
        self.target_path_ofd_button.grid(row = 0, column = 2, sticky = "EW")

        # other labels
        self.target_type_label.grid(row = 1, column = 0)
        self.target_key_label.grid(row = 3, column = 0)
        self.direction_label.grid(row = 4, column = 0)

        # encryption key
        self.key_options.grid(row = 3, column = 1, sticky = "EW")
        self.view_key_management_button.grid(row = 3, column = 2, sticky = "EW")

        # target type frame
        self.target_type_frame.grid(row = 1, column = 1)
        self.target_type_file_radio.grid(row = 0, column = 1)
        self.target_type_dir_radio.grid(row = 0, column = 2)

        # direction frame
        self.direction_frame.grid(row = 4, column = 1)
        self.direction_encrypt_radio.grid(row = 0, column = 1)
        self.direction_decrypt_radio.grid(row = 0, column = 2)

    def generate_keys(self, size):
        public_key, private_key = rsa.newkeys(size)

        with open(self.public_key_file, "w") as hFile:
            hFile.write(public_key.save_pkcs1().decode())

        with open(self.private_key_file, "w") as hFile:
            hFile.write(private_key.save_pkcs1().decode())

    def show_browse_dialog(self):
        if self.target_type == 0:
            selection = tk.filedialog.askopenfile(mode = "r")
        else:
            selection = tk.filedialog.askdirectory(mustexist = True)

        if selection is not None:
            self.target_path.delete(0, tk.END)
            self.target_path.insert(0, selection)

    def show_encryption_keys(self):
        pass

    def show_decryption_keys(self):
        pass

    def show_key_management_window(self):
        self.key_manager = tk.Toplevel(self.master)
        self.key_manager.grab_set()
        self.key_manager.title("Key Manager")
        self.key_manager.geometry("300x200")

        self.key_manager.columnconfigure((0, 1), weight = 1)

        # define widgets
        self.key_manager.saved_keys_listbox = tk.Listbox(self.key_manager, selectmode = tk.SINGLE)
        self.load_saved_keys_listbox()

        self.key_manager.add_key_button = tk.Button(self.key_manager, text = "Add New Key", command = self.show_add_key_window)
        self.key_manager.remove_key_button = tk.Button(self.key_manager, text = "Remove Key", command = self.remove_saved_key)

        # grid layout
        self.key_manager.saved_keys_listbox.grid(row = 0, column = 0, columnspan = 2, sticky = "ew")
        self.key_manager.add_key_button.grid(row = 1, column = 0, sticky = "ew")
        self.key_manager.remove_key_button.grid(row = 1, column = 1, sticky = "ew")

    def show_add_key_window(self):
        self.add_key_window = tk.Toplevel(self.master)
        self.add_key_window.grab_set()
        self.add_key_window.title("Add New Key")
        self.add_key_window.geometry("800x450")
        self.add_key_window.resizable(False, False)

        self.add_key_window.columnconfigure((0, 2), weight = 1)
        self.add_key_window.columnconfigure(1, weight = 3)

        # define widgets
        self.add_key_window.key_name_label = tk.Label(self.add_key_window, text = "Name: ")
        self.add_key_window.key_name_textbox = tk.Entry(self.add_key_window, borderwidth = 2)
        self.add_key_window.key_label = tk.Label(self.add_key_window, text = "Key: ")
        self.add_key_window.key_text = tk.Text(self.add_key_window)
        self.add_key_window.save_button = tk.Button(self.add_key_window, text = "Add Key", command = self.add_key)

        # grid layout
        self.add_key_window.key_name_label.grid(row = 0, column = 0)
        self.add_key_window.key_name_textbox.grid(row = 0, column = 1, sticky = "ew")
        self.add_key_window.key_label.grid(row = 1, column = 0)
        self.add_key_window.key_text.grid(row = 1, column = 1, sticky = "ew")
        self.add_key_window.save_button.grid(row = 2, column = 1, sticky = "ew")

    def load_saved_keys_listbox(self):
        self.saved_keys = []
        self.key_manager.saved_keys_listbox.delete(0, tk.END)

        with open(self.saved_keys_file) as hFile:
            saved_lines = [line.rstrip() for line in hFile]

        for i in range(len(saved_lines)):
            splits = saved_lines[i].split("\",\"")
            name = splits[0].lstrip("\"").rstrip("\"")
            key = splits[1].lstrip("\"").rstrip("\"")
            self.key_manager.saved_keys_listbox.insert(i + 1, name)
            self.saved_keys.append({ "name": name, "key": key })

    def remove_saved_key(self, key_name):
        pass

    def add_key(self):
        name = self.add_key_window.key_name_textbox.get().strip()
        key = self.add_key_window.key_text.get("1.0", tk.END).strip()

        if not name:
            messagebox.showerror(title = "Cannot Add Key", message = "All keys must have a name")
            return
        elif name in [k["name"] for k in self.saved_keys]:
            messagebox.showerror(title = "Cannot Add Key", message = "Key name already in use")
            return
        elif not key:
            messagebox.showerror(title = "Cannot Add Key", message = "All keys must have a key")
            return

        key = base64.b64encode(key.encode("ascii"))
        with open(self.saved_keys_file, "a") as hFile:
            hFile.write("\"%s\",\"%s\"\r\n" % (name, key))

        messagebox.showinfo(title = "Success", message = "Key Added")
        self.add_key_window.destroy()
        self.add_key_window.update()
        self.load_saved_keys_listbox()

if __name__ == "__main__":
    root = tk.Tk()
    MainApplication(root)
    root.mainloop()