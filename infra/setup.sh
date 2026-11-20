#!/usr/bin/env bash
# Sicherheitsoptionen für Bash:
# -e: Skript sofort stoppen, falls ein Befehl einen Fehler meldet
# -u: Fehler werfen, wenn eine unbekannte/leere Variable genutzt wird
# -o pipefail: Fehler auch innerhalb von Befehlsketten erkennen
set -euo pipefail

# ==============================================================================
# 0. Zentrale Variablen (einmal definieren, überall wiederverwenden)
# ==============================================================================
RG="rg-learningsteps"             # Name der Resource Group (Container für alle Ressourcen)
LOCATION="germanywestcentral"     # Azure-Region Frankfurt (DSGVO-freundlich & kurze Latenz)
VNET="vnet-learningsteps"         # Virtuelles Netzwerk (privater Adressraum in Azure)
SNET_PUB="snet-public"            # Öffentliches Subnet (Tier 1: API-Server)
SNET_PRIV="snet-private"          # Privates Subnet (Tier 2: Datenbank-Server)
NSG_API="nsg-api"                 # Virtuelle Firewall für das öffentliche Subnet
NSG_DB="nsg-db"                   # Virtuelle Firewall für das private Subnet

# Eigene aktuelle öffentliche IP-Adresse abfragen, damit SSH nur für mich offen ist
MY_IP=$(curl -s ifconfig.me)

# ==============================================================================
# 1. Resource Group, VNet und Subnets erstellen
# ==============================================================================
# Alle Ressourcen in einer Gruppe bündeln (erleichtert Verwaltung & späteres Aufräumen)
az group create --name "$RG" --location "$LOCATION"

# VNet (10.0.0.0/16 = 65.536 mögliche IPs) inklusive erstem Subnet (10.0.1.0/24) anlegen
az network vnet create --resource-group "$RG" --name "$VNET" \
  --address-prefix 10.0.0.0/16 \
  --subnet-name "$SNET_PUB" \
  --subnet-prefix 10.0.1.0/24

# Zweites, getrenntes Subnet (10.0.2.0/24) für die Datenbank hinzufügen
az network vnet subnet create --resource-group "$RG" --vnet-name "$VNET" \
  --name "$SNET_PRIV" \
  --address-prefix 10.0.2.0/24

# ==============================================================================
# 2. Network Security Groups (NSGs) nach dem Prinzip "Least Privilege"
# ==============================================================================
# NSG für Tier 1 (API): Nur Web-Traffic und mein eigener SSH-Zugang sind erlaubt
az network nsg create --resource-group "$RG" --name "$NSG_API"

az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_API" \
  --name Allow-HTTP --priority 100 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes Internet --destination-port-ranges 80

az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_API" \
  --name Allow-HTTPS --priority 110 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes Internet --destination-port-ranges 443

az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_API" \
  --name Allow-FastAPI --priority 120 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes Internet --destination-port-ranges 8000

az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_API" \
  --name Allow-SSH-MyIP --priority 130 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "${MY_IP}/32" --destination-port-ranges 22

# NSG für Tier 2 (Datenbank): Kein Zugriff aus dem Internet!
az network nsg create --resource-group "$RG" --name "$NSG_DB"

# PostgreSQL (Port 5432) darf NUR vom API-Subnet (10.0.1.0/24) angesprochen werden
az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_DB" \
  --name Allow-Postgres-From-API --priority 100 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 --destination-port-ranges 5432

# SSH (Port 22) darf ebenfalls NUR aus dem API-Subnet (über die API-VM als Jump-Host) kommen
az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_DB" \
  --name Allow-SSH-From-API --priority 110 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 --destination-port-ranges 22

# Explizite Deny-All-Regel (Prio 4000): Überschreibt Azures Standard-Regel "AllowVnetInBound" (Prio 65000),
# sodass sonst nichts aus dem restlichen VNet auf die Datenbank zugreifen kann.
az network nsg rule create --resource-group "$RG" --nsg-name "$NSG_DB" \
  --name Deny-All-Inbound --priority 4000 --direction Inbound --access Deny --protocol "*" \
  --source-address-prefixes "*" --destination-port-ranges "*"

# ==============================================================================
# 3. NSGs direkt an die Subnets binden
# ==============================================================================
az network vnet subnet update --resource-group "$RG" --vnet-name "$VNET" \
  --name "$SNET_PUB" --network-security-group "$NSG_API"

az network vnet subnet update --resource-group "$RG" --vnet-name "$VNET" \
  --name "$SNET_PRIV" --network-security-group "$NSG_DB"

# ==============================================================================
# 4. Private Datenbank-VM (vm-db) erstellen
# ==============================================================================
# --public-ip-address "" -> Verhindert eine öffentliche IP (DB bleibt rein intern)
# --nsg ""               -> Verhindert eine zweite NSG auf der Netzwerkkarte (läuft über Subnet)
# --size Standard_D2s_v6 -> Sparsame VM-Größe für das Azure-Student-Guthaben
az vm create --resource-group "$RG" --name vm-db --image Ubuntu2404 \
  --size Standard_D2s_v6 --storage-sku StandardSSD_LRS \
  --vnet-name "$VNET" --subnet "$SNET_PRIV" \
  --public-ip-address "" --nsg "" \
  --admin-username azureuser --generate-ssh-keys

# Tier 1: Öffentliche API-VM erstellen
az vm create \
  --resource-group rg-learningsteps \
  --name vm-api \
  --image Ubuntu2404 \
  --size Standard_D2s_v6 \
  --storage-sku StandardSSD_LRS \
  --vnet-name vnet-learningsteps \
  --subnet snet-public \
  --nsg nsg-api \
  --public-ip-address pip-api \
  --public-ip-sku Standard \
  --admin-username azureuser \
  --generate-ssh-keys
