resource "azurerm_storage_account" "example" {
  name                            = "examplestorage"
  resource_group_name             = "rg-example"
  location                        = "centralindia"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = "true"
  min_tls_version                 = "TLS1_0"
}

resource "azurerm_network_security_group_rule" "allow_all_inbound" {
  name                        = "allow-all-inbound"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-example"
  network_security_group_name = "nsg-example"
}

resource "azurerm_key_vault" "example" {
  name                     = "examplekv"
  location                 = "centralindia"
  resource_group_name      = "rg-example"
  sku_name                 = "standard"
  purge_protection_enabled = "false"
}
