import base64
import tkinter as tk
import json
import bcoding
import os
import threading
from datetime import timedelta
from tkinter import filedialog, ttk, messagebox

import main

ACTIVE_DOWNLOADS = []


def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Torrent files", "*.torrent")])
    if file_path:
        # NEW FRAME FOR LABEL AND BUTTONS
        file_frame = tk.Frame(content_frame)
        file_frame.pack(fill='x', padx=10, pady=2)

        # FILE PATH
        file_path_label = tk.Label(file_frame, text=f"File uploaded: {file_path}", anchor="w")
        file_path_label.pack(side='left', fill='x', expand=True)

        # "🖊️" BUTTON
        edit_button = tk.Button(file_frame, text="🖊️", command=lambda: open_edit_window(file_path))
        edit_button.pack(side='right', padx=5)

        # "📥" BUTTON
        download_button = tk.Button(file_frame, text="📥",
                                    command=lambda: select_directory_and_download(file_path, edit_button,
                                                                                  download_button, delete_button))
        download_button.pack(side='right')

        # Create "❌" button
        delete_button = tk.Button(file_frame, text="❌", command=lambda: delete_file_frame(file_frame))
        delete_button.pack(side='right')


def open_edit_window(file_path) -> None:
    def apply_changes() -> None:
        try:
            updated_content: json.loads = json.loads(text_area.get("1.0", tk.END))
            if 'info' in updated_content and 'pieces' in updated_content['info']:
                # CHANGE PIECES BACK TO HASH BYTES
                updated_content['info']['pieces'] = base64.b64decode(updated_content['info']['pieces'])
            with open(file_path, 'wb') as selected_file:
                selected_file.write(bcoding.bencode(updated_content))
            messagebox.showinfo("Info", "Changes applied successfully.")
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to save changes: {ex}")

    # CREATES EDITING WINDOW
    edit_window = tk.Toplevel(root)
    edit_window.title("Edit File")

    # ADJUSTS SIZE OF WINDOW
    edit_window.geometry("700x500")  # Adjusted dimensions to fit buttons comfortably

    # CREATES AREA FOR THE TEXT
    text_area = tk.Text(edit_window, wrap='word')
    text_area.pack(fill='both', expand=True, padx=10, pady=10)

    try:
        # LOADS CONTENT AND INSERTS INTO JSON
        with open(file_path, 'rb') as file:
            bencoded_content = file.read()
            decoded_content = bcoding.bdecode(bencoded_content)
            if 'info' in decoded_content and 'pieces' in decoded_content['info']:
                # ENCODES PIECES IN BASE64 SO IT COULD BE VIEWED IN EDITOR
                decoded_content['info']['pieces'] = base64.b64encode(decoded_content['info']['pieces']).decode('utf-8')
            text_area.insert(tk.END, json.dumps(decoded_content, indent=4))
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load file: {e}")

    # CREATES FRAME FOR BUTTONS
    button_frame = tk.Frame(edit_window)
    button_frame.pack(fill='x', padx=10, pady=5)

    # CREATES APPLY BUTTON
    apply_button = tk.Button(button_frame, text="Apply", command=apply_changes)
    apply_button.pack(side='left', padx=5)

    # CREATES OK BUTTON
    ok_button = tk.Button(button_frame, text="OK", command=lambda: edit_window.destroy())
    ok_button.pack(side='left', padx=5)


def select_directory_and_download(file_path, edit_button, download_button, delete_button) -> None:
    while True:
        # Ask user to select directory
        save_directory = filedialog.askdirectory()
        if not save_directory:
            return  # User cancelled the directory selection

        # Check if the directory is empty
        if not os.listdir(save_directory):
            start_download_threaded(save_directory, file_path, edit_button, download_button, delete_button)
            break
        else:
            messagebox.showwarning("Warning", "Please select an empty directory.")


def start_download_threaded(save_directory, file_path, edit_button, download_button, delete_button) -> None:
    # Create a thread for download operation
    cancel_event = threading.Event()
    download_thread = threading.Thread(target=start_download, args=(
        save_directory,
        file_path,
        edit_button,
        download_button,
        delete_button,
        cancel_event))
    download_thread.start()
    ACTIVE_DOWNLOADS.append((download_thread, cancel_event))


def start_download(save_directory, file_path, edit_button, download_button, delete_button, cancel_event) -> None:
    # HIDES BUTTONS
    edit_button.pack_forget()
    download_button.pack_forget()
    delete_button.pack_forget()

    # CREATES FRAME FOR DOWNLOAD CONTROLS
    control_frame = tk.Frame(content_frame)
    control_frame.pack(fill='x', padx=10, pady=5)

    state_label = tk.Label(control_frame, text="Collecting peers...", anchor="w")
    state_label.pack(side='left', padx=5)

    # CREATES CANCEL BUTTON
    pause_event = threading.Event()

    def pause_download():
        pause_event.set()

    def resume_download():
        pause_event.clear()

    def cancel_download():
        messagebox.showinfo("Info", "Be patient as we close down the connections.")
        cancel_event.set()
        progress_bar.destroy()
        control_frame.destroy()

    pause_button = tk.Button(control_frame, text="Pause", command=pause_download)
    pause_button.pack(side='left', padx=5)

    resume_button = tk.Button(control_frame, text="Resume", command=resume_download)
    resume_button.pack(side='left', padx=5)

    cancel_button = tk.Button(control_frame, text="Cancel", command=cancel_download)
    cancel_button.pack(side='left', padx=5)

    # CREATES PROGRESS BAR
    progress_bar = ttk.Progressbar(content_frame, orient='horizontal')
    progress_bar.pack(fill='x', padx=10, pady=5)
    percentage_label = tk.Label(control_frame, text="0%")
    percentage_label.pack(pady=10)
    time_elapsed_label = tk.Label(control_frame, text="Elapsed Time: 0 seconds")
    time_elapsed_label.pack(pady=10)
    estimated_time_left = tk.Label(control_frame, text="Estimated Time left: 0 seconds")
    estimated_time_left.pack(pady=10)

    def chop_microseconds(delta: timedelta) -> timedelta:
        return delta - timedelta(microseconds=delta.microseconds)

    def update(percent_value: int, state: str, time_elapsed: int):
        percent_value = percent_value
        progress_bar['value'] = percent_value
        percentage_label.config(text=f"{percent_value}%")
        state_label.config(text=f"{state}")
        time_elapsed_label.config(text=f"Elapsed Time: {chop_microseconds(timedelta(seconds=time_elapsed))}")
        estimated_time_left_calc = chop_microseconds(timedelta(
            seconds=((100 - percent_value)*time_elapsed)/(percent_value+0.1)))
        # IF THE DOWNLOAD SPEED IS CONSTANT, DELTA OF DATA DOWNLOADED DIVIDED BY DELTA OF TIME IS EQUAL.
        # MAKING THE DELTA OF TIME LEFT THE SUBJECT, WE CAN CALCULATE IT BY DELTA DATA LEFT TIMES DELTA TIME ELAPSED
        # DIVIDED BY DELTA DATA DOWNLOADED
        estimated_time_left.config(text=f"Estimated Time left: {estimated_time_left_calc}")


    try:
        # RUN TORRENT DOWNLOAD IN A THREAD
        exit_code: int = main.run(
                                save_directory,
                                file_path,
                                cancel_event,
                                pause_event,
                                update)

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
            progress_bar.destroy()
            control_frame.destroy()      # REMOVES UI
            match exit_code:
                case 0:
                    messagebox.showinfo("Info", "Torrent content successfully installed")
                case -1:
                    messagebox.showinfo("Info", "No peers to download from")
                case _:
                    messagebox.showinfo("Info", "Unexpected error occurred while downloading")
        ACTIVE_DOWNLOADS.remove((threading.current_thread(), cancel_event))

        # SHOW THE BUTTONS AGAIN
        edit_button.pack(side='right', padx=5)
        download_button.pack(side='right')
        delete_button.pack(side='right')

    except Exception as ex:
        messagebox.showerror("Error", f"Download failed: {ex}")


def delete_file_frame(file_frame):
    file_frame.destroy()


def on_closing():
    if ACTIVE_DOWNLOADS:
        messagebox.showwarning("Warning",
                            "Please wait for all downloads to complete or cancel them before closing the application.")
    else:
        root.destroy()


if __name__ == '__main__':
    # CREATE MAIN WINDOW
    root = tk.Tk()
    root.title("RK-Torrent")  # Set the title to "RK-Torrent"

    window_width = 1300
    window_height = 650
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_position = int((screen_width - window_width) / 2)
    y_position = int((screen_height - window_height) / 2)
    root.geometry(f"{window_width}x{window_height}+{x_position}+{y_position}")

    # CREATE TOP FRAME FOR BUTTON
    top_frame = tk.Frame(root)
    top_frame.pack(fill='x', pady=10)
    upload_button = tk.Button(top_frame, text="Upload File", command=upload_file)
    upload_button.pack(side='left', padx=10)

    # SEPARATOR LINE
    separator = ttk.Separator(root, orient='horizontal')
    separator.pack(fill='x', pady=5)

    # CREATE FRAME FOR CONTENT
    content_frame = tk.Frame(root)
    content_frame.pack(fill='both', expand=True, padx=10)

    # OVERRIDES CLOSING WINDOW
    root.protocol("WM_DELETE_WINDOW", on_closing)

    #
    logo = tk.PhotoImage(file="client_logo.png")
    root.iconphoto(False, logo)

    # RUN LOOP
    root.mainloop()
