# Deployment Guide

This guide covers deploying the Data Capturing and Measurement application to production.

## Pre-Deployment Checklist

- [ ] MongoDB Atlas cluster is created and configured
- [ ] Gmail App Password is generated
- [ ] Google OAuth credentials are configured
- [ ] All environment variables are set
- [ ] Application runs successfully locally
- [ ] All API endpoints are tested

## Environment Variables

Ensure all variables in `.env` are properly configured:

```env
JWT_SECRET_KEY=<strong-random-secret>
GOOGLE_CLIENT_ID=<your-google-client-id>
GOOGLE_CLIENT_SECRET=<your-google-client-secret>
MAIL_USERNAME=<your-gmail@gmail.com>
MAIL_PASSWORD=<gmail-app-password>
MAIL_DEFAULT_SENDER=<your-gmail@gmail.com>
MONGODB_URI=<mongodb-atlas-connection-string>
```

## Deployment Options

### Option 1: Deploy to Heroku

1. **Install Heroku CLI**
   ```bash
   # macOS
   brew install heroku/brew/heroku

   # Ubuntu
   curl https://cli-assets.heroku.com/install.sh | sh
   ```

2. **Login to Heroku**
   ```bash
   heroku login
   ```

3. **Create Heroku App**
   ```bash
   heroku create your-app-name
   ```

4. **Add Python Buildpack**
   ```bash
   heroku buildpacks:set heroku/python
   ```

5. **Set Environment Variables**
   ```bash
   heroku config:set JWT_SECRET_KEY="your-secret"
   heroku config:set MONGODB_URI="your-mongodb-uri"
   heroku config:set GOOGLE_CLIENT_ID="your-client-id"
   heroku config:set GOOGLE_CLIENT_SECRET="your-client-secret"
   heroku config:set MAIL_USERNAME="your-email"
   heroku config:set MAIL_PASSWORD="your-app-password"
   heroku config:set MAIL_DEFAULT_SENDER="your-email"
   ```

6. **Create Procfile**
   ```bash
   echo "web: gunicorn app:app" > Procfile
   ```

7. **Add gunicorn to requirements.txt**
   ```bash
   echo "gunicorn==21.2.0" >> requirements.txt
   ```

8. **Deploy**
   ```bash
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

9. **Update Google OAuth Redirect URI**
   - Go to Google Cloud Console
   - Add: `https://your-app-name.herokuapp.com/auth/google-callback`

---

### Option 2: Deploy to AWS EC2

1. **Launch EC2 Instance**
   - Ubuntu 22.04 LTS
   - t2.micro or larger
   - Configure security group (ports 22, 80, 443)

2. **Connect to Instance**
   ```bash
   ssh -i your-key.pem ubuntu@your-ec2-ip
   ```

3. **Install Dependencies**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv nginx -y
   ```

4. **Clone Repository**
   ```bash
   git clone <your-repo-url>
   cd data_capturing_and_measurement
   ```

5. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install gunicorn
   ```

6. **Configure Environment Variables**
   ```bash
   nano .env
   # Add all environment variables
   ```

7. **Create Systemd Service**
   ```bash
   sudo nano /etc/systemd/system/flask-app.service
   ```

   Add:
   ```ini
   [Unit]
   Description=Flask Data Capturing App
   After=network.target

   [Service]
   User=ubuntu
   WorkingDirectory=/home/ubuntu/data_capturing_and_measurement
   Environment="PATH=/home/ubuntu/data_capturing_and_measurement/venv/bin"
   ExecStart=/home/ubuntu/data_capturing_and_measurement/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app

   [Install]
   WantedBy=multi-user.target
   ```

8. **Configure Nginx**
   ```bash
   sudo nano /etc/nginx/sites-available/flask-app
   ```

   Add:
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;

       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
   }
   ```

9. **Enable and Start Services**
   ```bash
   sudo ln -s /etc/nginx/sites-available/flask-app /etc/nginx/sites-enabled/
   sudo systemctl start flask-app
   sudo systemctl enable flask-app
   sudo systemctl restart nginx
   ```

10. **Setup SSL with Let's Encrypt**
    ```bash
    sudo apt install certbot python3-certbot-nginx -y
    sudo certbot --nginx -d your-domain.com
    ```

---

### Option 3: Deploy to DigitalOcean App Platform

1. **Create DigitalOcean Account**
   - Sign up at digitalocean.com

2. **Create New App**
   - Go to App Platform
   - Click "Create App"
   - Connect GitHub repository

3. **Configure App**
   - Detected as Python app
   - Build command: `pip install -r requirements.txt`
   - Run command: `gunicorn app:app`

4. **Add Environment Variables**
   - Go to Settings → Environment Variables
   - Add all variables from `.env`

5. **Deploy**
   - Click "Deploy"
   - Wait for build to complete

6. **Update Google OAuth**
   - Add app URL to redirect URIs

---

### Option 4: Deploy with Docker

1. **Create Dockerfile**
   ```dockerfile
   FROM python:3.11-slim

   WORKDIR /app

   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   RUN pip install gunicorn

   COPY . .

   EXPOSE 5000

   CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
   ```

2. **Create docker-compose.yml**
   ```yaml
   version: '3.8'

   services:
     web:
       build: .
       ports:
         - "5000:5000"
       env_file:
         - .env
       restart: unless-stopped
   ```

3. **Build and Run**
   ```bash
   docker-compose up -d
   ```

---

## Production Configuration

### Update app.py for Production

Change the last lines of `app.py`:

```python
if __name__ == '__main__':
    app = create_app()
    # Production mode
    app.run(debug=False, host='0.0.0.0', port=5000)
```

### Security Considerations

1. **Use Strong JWT Secret**
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

2. **Enable HTTPS**
   - Always use SSL in production
   - Redirect HTTP to HTTPS

3. **Configure CORS Properly**
   In `app.py`, update CORS settings:
   ```python
   CORS(app, origins=["https://your-frontend-domain.com"])
   ```

4. **Set Secure Headers**
   Add Flask-Talisman:
   ```bash
   pip install flask-talisman
   ```

   In `app.py`:
   ```python
   from flask_talisman import Talisman
   Talisman(app)
   ```

5. **Rate Limiting**
   Add Flask-Limiter:
   ```bash
   pip install flask-limiter
   ```

   In `app.py`:
   ```python
   from flask_limiter import Limiter
   from flask_limiter.util import get_remote_address

   limiter = Limiter(
       app=app,
       key_func=get_remote_address,
       default_limits=["200 per day", "50 per hour"]
   )
   ```

6. **MongoDB Security**
   - Use IP whitelist
   - Enable authentication
   - Use strong passwords
   - Enable encryption at rest

7. **Logging**
   - Configure proper log rotation
   - Monitor error logs
   - Set up alerts for critical errors

---

## Monitoring

### Application Monitoring

1. **Sentry (Error Tracking)**
   ```bash
   pip install sentry-sdk[flask]
   ```

   In `app.py`:
   ```python
   import sentry_sdk
   from sentry_sdk.integrations.flask import FlaskIntegration

   sentry_sdk.init(
       dsn="your-sentry-dsn",
       integrations=[FlaskIntegration()]
   )
   ```

2. **Health Check Endpoint**
   Already included: `GET /health`

3. **Application Metrics**
   Use Prometheus or New Relic for monitoring

---

## Database Backup

### MongoDB Atlas Backups

1. **Enable Continuous Backups**
   - Go to MongoDB Atlas Dashboard
   - Select your cluster
   - Navigate to "Backup" tab
   - Enable continuous backups

2. **Manual Backups**
   ```bash
   mongodump --uri="<your-mongodb-uri>" --out=/backup/path
   ```

3. **Restore from Backup**
   ```bash
   mongorestore --uri="<your-mongodb-uri>" /backup/path
   ```

---

## Scaling

### Horizontal Scaling

1. **Multiple Workers**
   ```bash
   gunicorn -w 8 -b 0.0.0.0:5000 app:app
   ```

2. **Load Balancer**
   - Use Nginx or cloud load balancer
   - Distribute traffic across multiple instances

### Vertical Scaling

- Increase server resources (CPU, RAM)
- Upgrade MongoDB cluster tier

---

## Troubleshooting

### Application Won't Start

1. Check logs: `heroku logs --tail` or `journalctl -u flask-app`
2. Verify all environment variables are set
3. Test MongoDB connection
4. Check Python version compatibility

### Email Not Sending

1. Verify Gmail App Password
2. Check SMTP settings
3. Review firewall rules
4. Check application logs

### High Memory Usage

1. Reduce Gunicorn workers
2. Optimize database queries
3. Implement caching
4. Monitor with profiling tools

---

## Maintenance

### Update Dependencies

```bash
pip install --upgrade -r requirements.txt
```

### Database Migrations

When schema changes, use MongoDB migrations or manual updates.

### Log Rotation

Configure logrotate:
```bash
sudo nano /etc/logrotate.d/flask-app
```

Add:
```
/path/to/app.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ubuntu ubuntu
}
```

---

## Support

For issues or questions:
- Check logs first
- Review API_TESTING_GUIDE.md
- Consult README.md
- Check MongoDB Atlas status
- Verify Google OAuth configuration
