#
# Copyright (C) 2016 geewan.com
#
include $(TOPDIR)/rules.mk

PKG_NAME:=GTS
PKG_VERSION:=0.0.1

PKG_SOURCE_PROTO=git
PKG_SOURCE_URL:=https://github.com/geewan-rd/GTS.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=6631ceae5be18cd2850bfbaa45798993efc4e797
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/GTS
  SECTION:=net
  CATEGORY:=Network
  TITLE:=GTS-client
  URL:=https://github.com/geewan-rd/GTS
  DEPENDS:=+kmod-tun +ip +libsodium +libopenssl
endef

define Package/GTS/description
  Geewan Transimit System
endef

define Package/gts/install
	$(INSTALL_DIR) $(1)/etc/GTS
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client.json $(1)/etc/gts/client.json
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client_down.sh $(1)/etc/gts/client_down.sh
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client_up.sh $(1)/etc/gts/client_up.sh
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/gts-cli $(1)/usr/bin
endef

$(eval $(call BuildPackage,GTS))