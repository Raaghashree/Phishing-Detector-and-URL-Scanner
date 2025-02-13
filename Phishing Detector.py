import tkinter as tk
from tkinter import scrolledtext
import re
import requests
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# 🔹 Load Pre-trained Phishing Detection Model
tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")

# 🔹 VirusTotal API Key (Replace with your API key)
VIRUSTOTAL_API_KEY = "1ab84210ec4c265d4ed77dbf88eed32aa04089dc23f8d1730bed51a245539b88"

# 🔹 Function to Detect Phishing in Email Text
def detect_phishing(email_text):
    inputs = tokenizer(email_text, truncation=True, padding=True, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=-1)

    phishing_score = probabilities[0][1].item()
    return phishing_score

# 🔹 Function to Extract URLs from Text
def extract_urls(text):
    url_pattern = r"https?://[^\s]+"
    return re.findall(url_pattern, text)

# 🔹 Function to Check URL Safety with VirusTotal
def check_url_safety(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code == 200:
        url_id = response.json()["data"]["id"]
        report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            stats = report_response.json()["data"]["attributes"]["stats"]
            malicious_count = stats.get("malicious", 0)
            return malicious_count > 0  # True if flagged as malicious
    return False  # Assume safe if no result

# 🔹 GUI Function to Analyze Email
def analyze_email():
    email_text = input_box.get("1.0", tk.END).strip()
    if not email_text:
        result_box.insert(tk.END, "⚠️ Please enter email content.\n")
        return

    result_box.delete(1.0, tk.END)  # Clear previous results

    # 🔹 Phishing Detection
    phishing_score = detect_phishing(email_text)
    result_box.insert(tk.END, f"🔍 Phishing Probability: {phishing_score:.2f}\n")

    # 🔹 URL Extraction & VirusTotal Check
    urls = extract_urls(email_text)
    if urls:
        result_box.insert(tk.END, "\n🔗 URLs Found:\n")
        for url in urls:
            is_malicious = check_url_safety(url)
            if is_malicious:
                result_box.insert(tk.END, f"🚨 Malicious URL detected: {url}\n")
            else:
                result_box.insert(tk.END, f"✅ Safe URL: {url}\n")
    else:
        result_box.insert(tk.END, "\n✅ No URLs found.\n")

    # 🔹 Final Phishing Warning
    if phishing_score > 0.8:
        result_box.insert(tk.END, "\n🚨 HIGH chance of phishing! Be cautious.\n")
    elif phishing_score > 0.5:
        result_box.insert(tk.END, "\n⚠️ Suspicious email. Review carefully.\n")
    else:
        result_box.insert(tk.END, "\n✅ Email seems safe.\n")

# 🔹 GUI Setup
root = tk.Tk()
root.title("Phishing Detector with VirusTotal")

# 🔹 Input Box for Email Content
input_label = tk.Label(root, text="Paste Email Content Here:")
input_label.pack(pady=5)

input_box = scrolledtext.ScrolledText(root, width=80, height=10)
input_box.pack(padx=10, pady=5)

# 🔹 Analyze Button
analyze_button = tk.Button(root, text="Analyze Email", command=analyze_email)
analyze_button.pack(pady=10)

# 🔹 Result Display
result_box = scrolledtext.ScrolledText(root, width=80, height=10)
result_box.pack(padx=10, pady=10)

# 🔹 Run the GUI
root.mainloop()
