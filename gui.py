import base64
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import json
import bcoding
import os
import main  # Import the main module
import threading


def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Torrent files", "*.torrent")])
    if file_path:
        # Create a new frame to hold the label and buttons
        file_frame = tk.Frame(content_frame)
        file_frame.pack(fill='x', padx=10, pady=2)

        # Create a label to display the file path
        new_label = tk.Label(file_frame, text=f"File uploaded: {file_path}", anchor="w")
        new_label.pack(side='left', fill='x', expand=True)

        # Create "🖊️" button
        edit_button = tk.Button(file_frame, text="🖊️", command=lambda: open_edit_window(file_path))
        edit_button.pack(side='right', padx=5)

        # Create "📥" button
        download_button = tk.Button(file_frame, text="📥",
                                    command=lambda: select_directory_and_download(file_path, edit_button,
                                                                                  download_button, delete_button))
        download_button.pack(side='right')

        # Create "❌" button
        delete_button = tk.Button(file_frame, text="❌", command=lambda: delete_file_frame(file_frame))
        delete_button.pack(side='right')


def open_edit_window(file_path):
    def apply_changes():
        try:
            updated_content = json.loads(text_area.get("1.0", tk.END))
            if 'info' in updated_content and 'pieces' in updated_content['info']:
                # Convert pieces to string and then encode as bytes
                updated_content['info']['pieces'] = base64.b64decode(updated_content['info']['pieces'])
            with open(file_path, 'wb') as selected_file:
                selected_file.write(bcoding.bencode(updated_content))
            messagebox.showinfo("Info", "Changes applied successfully.")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to save changes: {ex}")

    # Create a new top-level window for editing
    edit_window = tk.Toplevel(root)
    edit_window.title("Edit File")

    # Adjust size of the edit window
    edit_window.geometry("700x500")  # Adjusted dimensions to fit buttons comfortably

    # Create a text area for editing
    text_area = tk.Text(edit_window, wrap='word')
    text_area.pack(fill='both', expand=True, padx=10, pady=10)

    try:
        # Load the content of the file, decode it, and insert it as JSON
        with open(file_path, 'rb') as file:
            bencoded_content = file.read()
            decoded_content = bcoding.bdecode(bencoded_content)
            if 'info' in decoded_content and 'pieces' in decoded_content['info']:
                # Convert pieces to string for editing
                decoded_content['info']['pieces'] = base64.b64encode(decoded_content['info']['pieces']).decode('utf-8')
            text_area.insert(tk.END, json.dumps(decoded_content, indent=4))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load file: {e}")

    # Create a frame for buttons
    button_frame = tk.Frame(edit_window)
    button_frame.pack(fill='x', padx=10, pady=5)

    # Create "Apply" button
    apply_button = tk.Button(button_frame, text="Apply", command=apply_changes)
    apply_button.pack(side='left', padx=5)

    # Create "OK" button (non-functional)
    ok_button = tk.Button(button_frame, text="OK", command=lambda: edit_window.destroy())
    ok_button.pack(side='left', padx=5)


def select_directory_and_download(file_path, edit_button, download_button, delete_button):
    while True:
        # Ask user to select directory
        save_directory = filedialog.askdirectory()
        if not save_directory:
            return  # User cancelled the directory selection

        # Check if the directory is empty
        if not os.listdir(save_directory):
            print(f"Selected directory: {save_directory}")
            start_download_threaded(save_directory, file_path, edit_button, download_button, delete_button)
            break
        else:
            messagebox.showwarning("Warning", "Please select an empty directory.")


def start_download_threaded(save_directory, file_path, edit_button, download_button, delete_button):
    # Create a thread for download operation
    download_thread = threading.Thread(target=start_download,
                                       args=(save_directory, file_path, edit_button, download_button, delete_button))
    download_thread.start()


def start_download(save_directory, file_path, edit_button, download_button, delete_button):
    # Hide the Edit, Download, and Delete buttons
    edit_button.pack_forget()
    download_button.pack_forget()
    delete_button.pack_forget()

    # Create a frame for download controls
    control_frame = tk.Frame(content_frame)
    control_frame.pack(fill='x', padx=10, pady=5)

    # Create label for "Collecting peers..."
    collecting_label = tk.Label(control_frame, text="Collecting peers...", anchor="w")
    collecting_label.pack(side='left', padx=5)



    # Create "Cancel" button
    pause_event = threading.Event()
    cancel_event = threading.Event()

    def pause_download():
        pause_event.set()

    def resume_download():
        pause_event.clear()

    def cancel_download():
        cancel_event.set()
        progress_bar.destroy()
        control_frame.destroy()

    # Create "Pause" button (non-functional)
    pause_button = tk.Button(control_frame, text="Pause", command=pause_download)
    pause_button.pack(side='left', padx=5)

    # Create "Resume" button (non-functional)
    resume_button = tk.Button(control_frame, text="Resume", command=resume_download)
    resume_button.pack(side='left', padx=5)

    cancel_button = tk.Button(control_frame, text="Cancel", command=cancel_download)
    cancel_button.pack(side='left', padx=5)

    # Create a progress bar
    progress_bar = ttk.Progressbar(content_frame, orient='horizontal', mode='indeterminate')
    progress_bar.pack(fill='x', padx=10, pady=5)

    try:
        # Run main.run() in the thread
        main.run(save_directory, file_path, cancel_event, pause_event)

        if cancel_event.is_set():
            try:
                files = os.listdir(save_directory)
                for file in files:
                    file_path = os.path.join(save_directory, file)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                messagebox.showinfo("Info", "Torrent content successfully deleted")
            except OSError:
                print("Error occurred while deleting files.")
        else:
            messagebox.showinfo("Info", "Torrent content successfully installed")
        # Cleanup after download completes or is cancelled


        # Show back the Edit and Download buttons
        edit_button.pack(side='right', padx=5)
        download_button.pack(side='right')
        delete_button.pack(side='right')

    except Exception as ex:
        messagebox.showerror("Error", f"Download failed: {ex}")


def delete_file_frame(file_frame):
    file_frame.destroy()


# Create the main window
root = tk.Tk()
root.title("RK-Torrent")  # Set the title to "RK-Torrent"

# Calculate the position to start the window in the middle of the screen
window_width = 1300
window_height = 650

screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

x_position = int((screen_width - window_width) / 2)
y_position = int((screen_height - window_height) / 2)

root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

# Create a top frame for the upload button
top_frame = tk.Frame(root)
top_frame.pack(fill='x', pady=10)

# Create the upload button and place it in the top left corner
upload_button = tk.Button(top_frame, text="Upload File", command=upload_file)
upload_button.pack(side='left', padx=10)

# Create a separator line
separator = ttk.Separator(root, orient='horizontal')
separator.pack(fill='x', pady=5)

# Create a frame to hold the content (uploaded file labels and buttons)
content_frame = tk.Frame(root)
content_frame.pack(fill='both', expand=True, padx=10)

# Run the Tkinter event loop
root.mainloop()
