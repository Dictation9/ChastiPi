# Remote Access Setup for ChastiPi

## 🌐 Overview

By default, ChastiPi runs locally on your Raspberry Pi. To allow keyholders to access the system from anywhere (different WiFi, mobile data, etc.), you need to configure remote access.

## 🔧 Option 1: Port Forwarding (Recommended)

### Step 1: Find Your Pi's IP Address
```bash
# On your Raspberry Pi
hostname -I
# or
ip addr show
```

### Step 2: Configure Router Port Forwarding
1. **Access your router admin panel** (usually `192.168.1.1` or `192.168.0.1`)
2. **Find Port Forwarding settings** (may be called "Virtual Server" or "NAT")
3. **Add a new rule**:
   - **External Port**: 5000 (or any port you prefer)
   - **Internal IP**: Your Pi's IP address (e.g., `192.168.1.100`)
   - **Internal Port**: 5000
   - **Protocol**: TCP

### Step 3: Update Configuration
Edit your `config.json`:
```json
{
    "host": "0.0.0.0",
    "port": 5000,
    "external_url": "https://your-public-ip:5000"
}
```

### Step 4: Access Remotely
- **Local**: `http://192.168.1.100:5000`
- **Remote**: `http://your-public-ip:5000`

## 🔒 Option 2: VPN Solution (Most Secure)

### Using Tailscale (Recommended)
```bash
# Install Tailscale on Raspberry Pi
curl -fsSL https://tailscale.com/install.sh | sh

# Start Tailscale
sudo tailscale up

# Get your Tailscale IP
tailscale ip
```

### Using WireGuard
```bash
# Install WireGuard
sudo apt install wireguard

# Generate keys
wg genkey | sudo tee /etc/wireguard/private.key
sudo cat /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
```

## 🌍 Option 3: Dynamic DNS + Port Forwarding

### Step 1: Set up Dynamic DNS
1. **Choose a provider**: No-IP, DuckDNS, or your router's built-in service
2. **Create a hostname**: `mychastipi.ddns.net`
3. **Configure on router**: Enable DDNS with your credentials

### Step 2: Update Configuration
```json
{
    "host": "0.0.0.0",
    "port": 5000,
    "external_url": "https://mychastipi.ddns.net:5000"
}
```

## 🔐 Option 4: Reverse Proxy with HTTPS (Production)

### Using Nginx + Let's Encrypt
```bash
# Install Nginx
sudo apt install nginx

# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Configure Nginx
sudo nano /etc/nginx/sites-available/chastipi
```

Nginx configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/chastipi /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com
```

## 📱 Option 5: Cloudflare Tunnel (Easiest)

### Step 1: Install Cloudflare Tunnel
```bash
# Download cloudflared
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb
sudo dpkg -i cloudflared-linux-arm64.deb
```

### Step 2: Authenticate
```bash
cloudflared tunnel login
```

### Step 3: Create Tunnel
```bash
cloudflared tunnel create chastipi
cloudflared tunnel route dns chastipi your-subdomain.your-domain.com
```

### Step 4: Configure Tunnel
Create `~/.cloudflared/config.yml`:
```yaml
tunnel: your-tunnel-id
credentials-file: ~/.cloudflared/your-tunnel-id.json

ingress:
  - hostname: your-subdomain.your-domain.com
    service: http://localhost:5000
  - service: http_status:404
```

### Step 5: Run Tunnel
```bash
cloudflared tunnel run chastipi
```

## 🔧 Configuration Updates

### Update Email Service
When using remote access, update your email configuration:

```json
{
    "email": {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "email_address": "your-email@gmail.com",
        "password": "your-app-password",
        "use_tls": true
    },
    "external_url": "https://your-domain.com",
    "webhook_url": "https://your-domain.com/webhook/email"
}
```

### Update Webhook URLs
For email reply processing, ensure webhooks point to your public URL:

```bash
# Test webhook accessibility
curl -X GET https://your-domain.com/webhook/test
```

## 🛡️ Security Considerations

### 1. Firewall Configuration
```bash
# Allow only necessary ports
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP (if using reverse proxy)
sudo ufw allow 443   # HTTPS (if using reverse proxy)
sudo ufw enable
```

### 2. SSL/TLS Encryption
- **Always use HTTPS** for remote access
- **Let's Encrypt** provides free SSL certificates
- **Cloudflare** offers additional security layers

### 3. Authentication (Optional)
Consider adding basic authentication:
```python
# In your Flask app
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    return username == 'keyholder' and password == 'secure-password'

@app.route('/keyholder/')
@auth.login_required
def keyholder_dashboard():
    # Your dashboard code
```

## 🧪 Testing Remote Access

### Test Local Access
```bash
# On Pi
curl http://localhost:5000
```

### Test Remote Access
```bash
# From external network
curl http://your-public-ip:5000
# or
curl https://your-domain.com
```

### Test Email Webhooks
```bash
curl -X POST https://your-domain.com/webhook/email/test \
  -H "Content-Type: application/json" \
  -d '{"from_email": "keyholder@example.com", "reply_text": "approve"}'
```

## 📱 Mobile Access

### PWA Features
The web interface is mobile-responsive and can be installed as a PWA:

1. **Add to Home Screen** on iOS/Android
2. **Offline functionality** for basic features
3. **Push notifications** for key requests

### Mobile-Specific Features
- **Touch-friendly interface**
- **Camera integration** for photo uploads
- **QR code scanning** for punishment verification

## 🚨 Troubleshooting

### Common Issues

1. **Port not accessible**:
   - Check firewall settings
   - Verify port forwarding
   - Test with `telnet your-ip 5000`

2. **SSL certificate errors**:
   - Ensure domain is correct
   - Check certificate expiration
   - Verify DNS settings

3. **Email webhooks not working**:
   - Test webhook endpoint accessibility
   - Check email provider configuration
   - Verify webhook URL in email settings

### Debug Commands
```bash
# Check if service is running
sudo systemctl status chastipi

# Check logs
tail -f logs/chasti_pi.log

# Test network connectivity
ping your-domain.com
nslookup your-domain.com

# Check port accessibility
netstat -tlnp | grep 5000
```

## 📞 Support

For additional help with remote access setup:
1. Check router manufacturer documentation
2. Consult your ISP for port forwarding assistance
3. Review security best practices for your chosen method 