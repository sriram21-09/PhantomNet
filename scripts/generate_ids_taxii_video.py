import os
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

def generate_video():
    print("Generating demo_ids_taxii.mp4...")
    width, height = 1920, 1080
    fps = 10
    duration_per_phase = 3
    frames = []

    phases = [
        ("Phase 1: Automated Snort & Sigma Rule Generation", "Generating rules from detected attack payloads..."),
        ("Phase 2: Rule Deduplication", "Deduplicating duplicate rule signatures..."),
        ("Phase 3: Combined ZIP Download", "Downloading IDS rules in a single ZIP archive..."),
        ("Phase 4: TAXII 2.1 Feed Consumption", "Executing taxii2-client verification and STIX 2.1 bundle consumption...")
    ]

    for phase_title, phase_desc in phases:
        for _ in range(fps * duration_per_phase):
            img = Image.new('RGB', (width, height), color=(15, 23, 42))
            draw = ImageDraw.Draw(img)
            
            try:
                font_title = ImageFont.truetype("arialbd.ttf", 60)
                font_desc = ImageFont.truetype("arial.ttf", 40)
            except:
                font_title = ImageFont.load_default()
                font_desc = ImageFont.load_default()
                
            draw.text((100, 400), phase_title, fill=(0, 229, 255), font=font_title)
            draw.text((100, 500), phase_desc, fill=(241, 245, 249), font=font_desc)
            
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            frames.append(frame)

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")
    os.makedirs(output_dir, exist_ok=True)
    mp4_path = os.path.join(output_dir, "demo_ids_taxii.mp4")

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(mp4_path, fourcc, fps, (width, height))
    for frame in frames:
        out.write(frame)
    out.release()
    print(f"Video saved to {mp4_path}")

if __name__ == "__main__":
    generate_video()
