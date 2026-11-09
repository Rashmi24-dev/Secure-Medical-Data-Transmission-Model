import os
import requests

# Create folder
os.makedirs("medical_images", exist_ok=True)

# List of high-quality, free MRI / X-ray / Medical images
# These are from Unsplash (Free to use!)
images = {
    "mri_brain.png": "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?auto=format&fit=crop&w=800&q=80",
    "chest_xray.png": "https://images.unsplash.com/photo-1530497610245-94d3c16cda28?auto=format&fit=crop&w=800&q=80",
    "medical_scan.png": "https://images.unsplash.com/photo-1579154204601-01588f351e67?auto=format&fit=crop&w=800&q=80",
    "doctor_xray.png": "https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?auto=format&fit=crop&w=800&q=80",
}

print("⏳ Downloading medical images...")

for filename, url in images.items():
    response = requests.get(url)
    if response.status_code == 200:
        with open(os.path.join("medical_images", filename), 'wb') as f:
            f.write(response.content)
        print(f"✅ Downloaded {filename}")
    else:
        print(f"❌ Failed to download {filename}")

print("🎉 Images saved to the 'medical_images' folder!")