#!/bin/bash
# Azure deployment script using Docker Container Registry

# Variables (update these)
RESOURCE_GROUP="qsm-backend"  # Your existing resource group
APP_NAME="qsm-backend"        # Your existing app name
REGISTRY_NAME="qmsregistry"   # Your registry name (needs to be unique)
LOCATION="eastus"             # Choose from: eastus, westus2, centralus, etc.
IMAGE_NAME="qsm-backend"
TAG="latest"

# Step 1: Create Azure Container Registry if it doesn't exist
echo "Creating Azure Container Registry..."
az acr create --resource-group $RESOURCE_GROUP --name $REGISTRY_NAME --sku Basic --location $LOCATION

# Step 2: Build and tag the Docker image
echo "Building Docker image..."
docker build -f Dockerfile.simple -t $IMAGE_NAME:$TAG .

# Step 3: Log in to Azure Container Registry
echo "Logging in to Azure Container Registry..."
az acr login --name $REGISTRY_NAME

# Step 4: Tag the image for ACR
echo "Tagging image for ACR..."
docker tag $IMAGE_NAME:$TAG $REGISTRY_NAME.azurecr.io/$IMAGE_NAME:$TAG

# Step 5: Push the image to ACR
echo "Pushing image to ACR..."
docker push $REGISTRY_NAME.azurecr.io/$IMAGE_NAME:$TAG

# Step 6: Update the web app to use the container
echo "Updating the web app to use the container..."
az webapp config container set --name $APP_NAME --resource-group $RESOURCE_GROUP \
  --docker-custom-image-name $REGISTRY_NAME.azurecr.io/$IMAGE_NAME:$TAG \
  --docker-registry-server-url https://$REGISTRY_NAME.azurecr.io \
  --docker-registry-server-user $(az acr credential show --name $REGISTRY_NAME --query username --output tsv) \
  --docker-registry-server-password $(az acr credential show --name $REGISTRY_NAME --query passwords[0].value --output tsv)

# Step 7: Restart the web app
echo "Restarting the web app..."
az webapp restart --name $APP_NAME --resource-group $RESOURCE_GROUP

echo "Deployment completed!"
echo "App URL: https://$APP_NAME.azurewebsites.net"