#!/usr/bin/env python3
"""
Create a proper app icon for ChastiPi Mac App
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_app_icon():
    """Create a simple app icon with a lock symbol"""
    
    # Icon sizes for macOS
    sizes = [16, 32, 64, 128, 256, 512, 1024]
    
    # Create base image (1024x1024)
    base_size = 1024
    img = Image.new('RGBA', (base_size, base_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Create a rounded rectangle background
    margin = base_size // 8
    rect_size = base_size - (2 * margin)
    
    # Background gradient (dark blue to purple)
    for i in range(rect_size):
        alpha = int(255 * (1 - i / rect_size))
        color = (40, 44, 52, alpha)  # Dark background
        draw.rectangle([margin + i, margin + i, 
                       base_size - margin - i, base_size - margin - i], 
                      fill=color)
    
    # Draw lock symbol
    lock_color = (255, 255, 255, 255)  # White
    lock_size = base_size // 3
    
    # Lock body
    lock_x = base_size // 2
    lock_y = base_size // 2 + lock_size // 4
    
    # Lock body rectangle
    body_width = lock_size // 2
    body_height = lock_size // 1.5
    draw.rectangle([lock_x - body_width//2, lock_y - body_height//2,
                   lock_x + body_width//2, lock_y + body_height//2],
                  fill=lock_color, outline=lock_color, width=3)
    
    # Lock shackle (top part)
    shackle_width = lock_size // 1.5
    shackle_height = lock_size // 3
    shackle_y = lock_y - body_height//2 - shackle_height//2
    
    # Left side of shackle
    draw.rectangle([lock_x - shackle_width//2, shackle_y,
                   lock_x - shackle_width//2 + 8, shackle_y + shackle_height],
                  fill=lock_color)
    
    # Right side of shackle
    draw.rectangle([lock_x + shackle_width//2 - 8, shackle_y,
                   lock_x + shackle_width//2, shackle_y + shackle_height],
                  fill=lock_color)
    
    # Top of shackle
    draw.rectangle([lock_x - shackle_width//2, shackle_y,
                   lock_x + shackle_width//2, shackle_y + 8],
                  fill=lock_color)
    
    # Keyhole
    keyhole_size = lock_size // 6
    keyhole_x = lock_x
    keyhole_y = lock_y + lock_size // 8
    
    # Keyhole circle
    draw.ellipse([keyhole_x - keyhole_size, keyhole_y - keyhole_size,
                  keyhole_x + keyhole_size, keyhole_y + keyhole_size],
                 fill=(40, 44, 52, 255), outline=lock_color, width=2)
    
    # Keyhole slot
    slot_width = keyhole_size // 2
    slot_height = keyhole_size * 1.5
    draw.rectangle([keyhole_x - slot_width//2, keyhole_y,
                   keyhole_x + slot_width//2, keyhole_y + slot_height],
                  fill=(40, 44, 52, 255), outline=lock_color, width=2)
    
    # Add some glow effect
    glow_size = base_size // 20
    for i in range(glow_size):
        alpha = int(100 * (1 - i / glow_size))
        glow_color = (100, 150, 255, alpha)
        draw.ellipse([lock_x - lock_size//2 - i, lock_y - lock_size//2 - i,
                     lock_x + lock_size//2 + i, lock_y + lock_size//2 + i],
                    fill=glow_color)
    
    # Create iconsets directory
    iconset_dir = "ChastiPi.iconset"
    if os.path.exists(iconset_dir):
        import shutil
        shutil.rmtree(iconset_dir)
    os.makedirs(iconset_dir)
    
    # Generate different sizes
    for size in sizes:
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        
        # Save regular size
        resized.save(f"{iconset_dir}/icon_{size}x{size}.png")
        
        # Save @2x size for retina displays
        if size * 2 <= 1024:
            resized_2x = img.resize((size * 2, size * 2), Image.Resampling.LANCZOS)
            resized_2x.save(f"{iconset_dir}/icon_{size}x{size}@2x.png")
    
    # Convert to .icns
    os.system(f"iconutil -c icns {iconset_dir}")
    
    # Clean up
    import shutil
    shutil.rmtree(iconset_dir)
    
    print("✅ App icon created: ChastiPi.icns")
    return "ChastiPi.icns"

if __name__ == "__main__":
    create_app_icon() 