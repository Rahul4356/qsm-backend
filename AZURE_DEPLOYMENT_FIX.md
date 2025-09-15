# Fix Azure Deployment - GitHub Actions Credentials

## 🔧 **Issue Identified**
Your build is successful but deployment fails due to missing Azure publish profile secret.

Your workflows expect this secret: `AZUREAPPSERVICE_PUBLISHPROFILE_4848AD556E03415CBC5D6ACE9CCABC03`

## 🚀 **Solution 1: Get Publish Profile from Azure Portal (Easiest)**

### **Step 1: Download Publish Profile**
```bash
# Login to Azure CLI
az login

# Download publish profile
az webapp deployment list-publishing-profiles \
    --name qsm-backend \
    --resource-group qms-rg \
    --xml
```

### **Step 2: Add Secret to GitHub**
1. Go to: https://github.com/Rahul4356/qsm-backend/settings/secrets/actions
2. Click "New repository secret"
3. Name: `AZUREAPPSERVICE_PUBLISHPROFILE_4848AD556E03415CBC5D6ACE9CCABC03`
4. Value: Paste the entire XML content from Step 1
5. Click "Add secret"

### **Step 3: Alternative - Get from Azure Portal**
1. Go to Azure Portal → App Services → qsm-backend
2. Click "Get publish profile" in the overview
3. Download the .publishsettings file
4. Copy its content to GitHub secret

## 🚀 **Solution 2: Manual Deployment (Immediate)**

Deploy directly using Azure CLI while you set up the secrets:

```bash
# Create deployment package
zip -r qms-app.zip . -x "*.git*" "*venv*" "*__pycache__*" "*.DS_Store*"

# Deploy to Azure
az webapp deployment source config-zip \
    --resource-group qms-rg \
    --name qsm-backend \
    --src qms-app.zip
```

## 🚀 **Solution 3: Git Deployment (Alternative)**

```bash
# Set up Azure remote
az webapp deployment source config-local-git \
    --name qsm-backend \
    --resource-group qms-rg

# This will give you a URL like:
# https://qsm-backend.scm.azurewebsites.net/qsm-backend.git

# Add as remote and deploy
git remote add azure https://qsm-backend.scm.azurewebsites.net/qsm-backend.git
git push azure main
```

## 🧪 **Test After Deployment**

```bash
# 1. Health check
curl https://qsm-backend.azurewebsites.net/api/health

# 2. Quantum info
curl https://qsm-backend.azurewebsites.net/api/quantum/info

# 3. Register test user
curl -X POST https://qsm-backend.azurewebsites.net/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"test123"}'
```

## 🔍 **Verify Deployment Success**

Check Azure logs:
```bash
az webapp log tail --name qsm-backend --resource-group qms-rg
```

Check app status:
```bash
az webapp show --name qsm-backend --resource-group qms-rg --query "state"
```

## 📊 **Expected Results**

After successful deployment:
- ✅ Health endpoint returns `{"status": "ok"}`
- ✅ Quantum endpoint shows ML-KEM-768 and Falcon-512 support
- ✅ User registration works
- ✅ WebSocket connections can be established
- ✅ Database is created and accessible

Your Quantum Messaging System with post-quantum cryptography will be fully operational! 🔐🚀