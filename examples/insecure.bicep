resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'examplestorage'
  location: 'centralindia'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: true
  }
}

resource allowAllInbound 'Microsoft.Network/networkSecurityGroups/securityRules@2023-05-01' = {
  name: 'nsg-example/allow-all-inbound'
  properties: {
    priority: 100
    direction: 'Inbound'
    access: 'Allow'
    protocol: '*'
    sourcePortRange: '*'
    destinationPortRange: '*'
    sourceAddressPrefix: '*'
    destinationAddressPrefix: '*'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'examplekv'
  location: 'centralindia'
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: '00000000-0000-0000-0000-000000000000'
    enablePurgeProtection: false
  }
}
