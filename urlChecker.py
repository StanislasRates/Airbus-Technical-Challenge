import tkinter as tk
import requests
import base64
import json

API_KEY = "YOUR_API_KEY"

headers = {"accept": "application/json",
           "x-apikey": API_KEY}


def check_url(urlToCheck):
    try:
        data = json.loads(urlToCheck)
        if "url" not in data:
            return "Invalid input format. Please provide a JSON object with a 'url' key."
        urlToCheck = data["url"]

        url_id = base64.urlsafe_b64encode(urlToCheck.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=headers)
    
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result = f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Harmless: {stats['harmless']}, Undetected: {stats['undetected']}"
            return result
    except json.JSONDecodeError:
        result = "Invalid JSON input. Please provide a valid JSON object, e.g., {\"url\": \"http://example.com\"}."
    except Exception as e:
        result = f"An error occurred: {str(e)}. Please try again."

    return result

def on_button_click():
    user_input = textBox.get("1.0", tk.END).strip()
    if not user_input:
        textBox.delete("1.0", tk.END)
        textBox.insert(tk.END, "Please enter a JSON input.")
        return
    
    result = check_url(user_input)
    textBox.delete("1.0", tk.END)
    textBox.insert(tk.END, result)


# Interface tkinter
def main():
    global textBox
    root = tk.Tk()
    root.title("URL checker")
    root.geometry("450x200")

    label = tk.Label(root, text="Enter JSON (e.g., {\"url\": \"http://example.com\"}):")
    label.pack(pady=10)

    textBox = tk.Text(root, height=3, width=40)
    textBox.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
    textBox.insert(tk.END, '{"url": "http://example.com"}')

    button = tk.Button(root, text="Check URL", command=on_button_click)
    button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()