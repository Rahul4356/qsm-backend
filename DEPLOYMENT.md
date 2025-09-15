# Quantum Messaging System - Production Deployment Guide

## Overview
This guide covers the complete deployment of the Quantum Messaging System to Azure, featuring post-quantum cryptography, real-time messaging, and enterprise security.

## Architecture
- **Backend**: FastAPI with quantum cryptography (Azure App Service)
- **Frontend**: Static HTML/JS (Azure Static Web Apps)
- **Database**: SQLite (production should use Azure SQL)
- **Security**: ML-KEM-768 + Falcon-512 quantum-resistant crypto

## Pre-Deployment Checklist

### 1. Prerequisites
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login to Azure
az login

# Install Git (if not already installed)
sudo apt-get install git
```

### 2. Environment Configuration
```bash
# Generate secure secret key
export SECRET_KEY=$(openssl rand -hex 32)
echo "Generated SECRET_KEY: $SECRET_KEY"

# Set environment variables
export RESOURCE_GROUP="qms-rg"
export APP_NAME="qms-backend"
export LOCATION="eastus"
export PLAN_NAME="qms-plan"
```

## Backend Deployment (Azure App Service)

### Step 1: Create Azure Resources
```bash
# Create resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create App Service Plan (B1 for production, F1 for testing)
az appservice plan create \
    --name $PLAN_NAME \
    --resource-group $RESOURCE_GROUP \
    --sku B1 \
    --is-linux

# Create Web App
az webapp create \
    --resource-group $RESOURCE_GROUP \
    --plan $PLAN_NAME \
    --name $APP_NAME \
    --runtime "PYTHON:3.11"
```

### Step 2: Configure Application Settings
```bash
# Set environment variables
az webapp config appsettings set \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --settings \
    AZURE_ENV=production \
    SECRET_KEY=$SECRET_KEY \
    LOG_LEVEL=INFO \
    DB_PATH=/home/data/qms.db \
    SCM_DO_BUILD_DURING_DEPLOYMENT=true \
    WEBSITE_RUN_FROM_PACKAGE=0

# Enable WebSocket for real-time messaging
az webapp config set \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --web-sockets-enabled true

# Set startup command
az webapp config set \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --startup-file "bash startup.sh"
```

### Step 3: Deploy via GitHub Actions (Current Setup)
Your GitHub Actions workflow is already configured. Simply push your code:

```bash
git add .
git commit -m "Production deployment with quantum crypto"
git push origin main
```

### Step 4: Alternative - Direct Git Deployment
```bash
# Configure local Git deployment
az webapp deployment source config-local-git \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP

# Add Azure remote (replace with your actual URL)
git remote add azure https://$APP_NAME.scm.azurewebsites.net/$APP_NAME.git

# Deploy
git push azure main
```

## Frontend Deployment (Azure Static Web Apps)

### Step 1: Prepare Frontend
Update your `index.html` with the production backend URL:

```javascript
// Update configuration in index.html
const API_BASE = 'https://qms-backend.azurewebsites.net';
const QUANTUM_API = 'https://qms-backend.azurewebsites.net';
const WS_BASE = 'wss://qms-backend.azurewebsites.net';
```

### Step 2: Create Static Web App
```bash
# Create Static Web App
az staticwebapp create \
    --name qms-frontend \
    --resource-group $RESOURCE_GROUP \
    --source https://github.com/Rahul4356/qms-frontend \
    --branch main \
    --app-location "/" \
    --output-location "/" \
    --login-with-github
```

### Step 3: Configure CORS
```bash
# Allow frontend to access backend
az webapp cors add \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --allowed-origins https://jolly-bay-05893c200.1.azurestaticapps.net \
    --allowed-origins https://localhost:3000
```

## Security Configuration

### Step 1: Azure Key Vault (Recommended for Production)
```bash
# Create Key Vault
az keyvault create \
    --name qms-keyvault \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION

# Store secret key
az keyvault secret set \
    --vault-name qms-keyvault \
    --name secret-key \
    --value $SECRET_KEY

# Grant access to Web App
az webapp identity assign \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME

# Get the principal ID and grant access
PRINCIPAL_ID=$(az webapp identity show --resource-group $RESOURCE_GROUP --name $APP_NAME --query principalId --output tsv)

az keyvault set-policy \
    --name qms-keyvault \
    --object-id $PRINCIPAL_ID \
    --secret-permissions get
```

### Step 2: HTTPS and Security Headers
```bash
# Enable HTTPS only
az webapp update \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP \
    --https-only true

# Configure security headers (done in app.py)
```

## Database Configuration

### For Production - Migrate to Azure SQL
```bash
# Create Azure SQL Database
az sql server create \
    --name qms-sql-server \
    --resource-group $RESOURCE_GROUP \
    --location $LOCATION \
    --admin-user qmsadmin \
    --admin-password $(openssl rand -base64 16)

az sql db create \
    --resource-group $RESOURCE_GROUP \
    --server qms-sql-server \
    --name qms-database \
    --service-objective Basic

# Update connection string in app settings
az webapp config connection-string set \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --connection-string-type SQLServer \
    --settings DefaultConnection="Server=tcp:qms-sql-server.database.windows.net,1433;Database=qms-database;User ID=qmsadmin;Password=<password>;Encrypt=true;TrustServerCertificate=false;Connection Timeout=30;"
```

## Monitoring and Logging

### Step 1: Application Insights
```bash
# Create Application Insights
az monitor app-insights component create \
    --app qms-insights \
    --location $LOCATION \
    --resource-group $RESOURCE_GROUP

# Get instrumentation key
INSTRUMENTATION_KEY=$(az monitor app-insights component show --app qms-insights --resource-group $RESOURCE_GROUP --query instrumentationKey --output tsv)

# Add to app settings
az webapp config appsettings set \
    --resource-group $RESOURCE_GROUP \
    --name $APP_NAME \
    --settings APPINSIGHTS_INSTRUMENTATIONKEY=$INSTRUMENTATION_KEY
```

### Step 2: Log Streaming
```bash
# View real-time logs
az webapp log tail \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP

# Download logs
az webapp log download \
    --name $APP_NAME \
    --resource-group $RESOURCE_GROUP
```

## Testing the Deployment

### Health Check
```bash
curl https://qms-backend.azurewebsites.net/api/health
```

### Quantum Crypto Test
```bash
curl https://qms-backend.azurewebsites.net/api/quantum/info
```

### User Registration
```bash
curl -X POST https://qms-backend.azurewebsites.net/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"quantum123"}'
```

### WebSocket Test
Open browser developer tools and test:
```javascript
const ws = new WebSocket('wss://qms-backend.azurewebsites.net/ws/chat/test-room?token=<your-jwt-token>');
ws.onopen = () => console.log('Connected');
ws.onmessage = (e) => console.log('Message:', e.data);
```

## Production Optimization

### Performance
- Enable Azure CDN for static assets
- Configure autoscaling rules
- Implement response caching
- Use Azure Front Door for global distribution

### Security
- Configure Azure WAF (Web Application Firewall)
- Enable Azure DDoS Protection
- Set up Azure Security Center monitoring
- Implement Azure AD integration

### Reliability
- Set up backup strategies
- Configure disaster recovery
- Implement health checks
- Set up alerting rules

## Troubleshooting

### Common Issues
1. **500 Internal Server Error**: Check logs with `az webapp log tail`
2. **Module not found**: Ensure requirements.txt is complete
3. **Database errors**: Check DB_PATH and permissions
4. **WebSocket issues**: Verify web-sockets-enabled setting

### Debug Commands
```bash
# SSH into the container
az webapp ssh --resource-group $RESOURCE_GROUP --name $APP_NAME

# Check processes
ps aux | grep python

# Check disk space
df -h

# Check environment variables
env | grep AZURE
```

## Cost Optimization

### Free Tier Resources
- Azure Static Web Apps (free tier)
- Azure App Service F1 (free tier, but limited)
- Azure SQL Database Basic (paid, but minimal cost)

### Production Recommendations
- App Service B1: ~$13/month
- Azure SQL Basic: ~$5/month
- Application Insights: Free tier up to 1GB/month

## Security Checklist

- [ ] HTTPS enforced
- [ ] Secrets in Azure Key Vault
- [ ] CORS properly configured
- [ ] Rate limiting enabled
- [ ] Input validation implemented
- [ ] SQL injection protection
- [ ] Authentication required for sensitive endpoints
- [ ] Quantum-resistant cryptography enabled
- [ ] Logging and monitoring configured

Your Quantum Messaging System is now ready for production deployment with enterprise-grade security and quantum-resistant cryptography!