import tkinter as tk
from tkinter import filedialog, ttk

def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Torrent files", "*.torrent")])
    file_name = file_path.split("/")[-1]
    if file_path:
        # Create a new frame to hold the label and buttons
        file_frame = tk.Frame(content_frame)
        file_frame.pack(fill='x', padx=10, pady=2)

        # Create a label to display the file path
        new_label = tk.Label(file_frame, text=file_name, anchor="w")
        new_label.pack(side='left', fill='x', expand=True)

        # Create "❌" button
        delete_button = tk.Button(file_frame, text="❌", command=lambda: delete_file_frame(file_frame))
        delete_button.pack(side='right')

        # Create "🖊️" button
        edit_button = tk.Button(file_frame, text="🖊️", command=lambda: open_edit_window(file_path))
        edit_button.pack(side='right', padx=5)

        # Create "📥" button
        download_button = tk.Button(file_frame, text="📥", command=lambda: select_directory_and_download(file_path, edit_button, download_button, delete_button))
        download_button.pack(side='right')



def open_edit_window(file_path):
    # Create a new top-level window for editing
    edit_window = tk.Toplevel(root)
    edit_window.title("Edit File")

    # Adjust size of the edit window
    edit_window.geometry("700x500")  # Adjusted dimensions to fit buttons comfortably

    # Create a text area for editing
    text_area = tk.Text(edit_window, wrap='word')
    text_area.pack(fill='both', expand=True, padx=10, pady=10)

    # Create a frame for buttons
    button_frame = tk.Frame(edit_window)
    button_frame.pack(fill='x', padx=10, pady=5)

    # Create "Apply" button (non-functional)
    apply_button = tk.Button(button_frame, text="Apply", command=lambda: None)
    apply_button.pack(side='left', padx=5)

    # Create "OK" button (non-functional)
    ok_button = tk.Button(button_frame, text="OK", command=lambda: None)
    ok_button.pack(side='left', padx=5)

def select_directory_and_download(file_path, edit_button, download_button, delete_button):
    # Ask user to select directory
    save_directory = filedialog.askdirectory()
    if save_directory:
        print(f"Selected directory: {save_directory}")

        # Proceed with "downloading"
        start_download(save_directory, edit_button, download_button, delete_button)

def start_download(save_directory, edit_button, download_button, delete_button):
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

    # Create "Pause" button (non-functional)
    pause_button = tk.Button(control_frame, text="Pause", command=lambda: None)
    pause_button.pack(side='left', padx=5)

    # Create "Resume" button (non-functional)
    resume_button = tk.Button(control_frame, text="Resume", command=lambda: None)
    resume_button.pack(side='left', padx=5)

    # Create "Cancel" button (non-functional)
    cancel_button = tk.Button(control_frame, text="Cancel", command=lambda: None)
    cancel_button.pack(side='left', padx=5)

    # Create a progress bar with indeterminate mode
    progress_bar = ttk.Progressbar(content_frame, orient='horizontal', mode='indeterminate')
    progress_bar.pack(fill='x', padx=10, pady=5)

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
