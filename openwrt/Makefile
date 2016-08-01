#
# Copyright (C) 2016 geewan.com
#
include $(TOPDIR)/rules.mk

PKG_NAME:=GTS
PKG_VERSION:=1.0

PKG_SOURCE_PROTO=git
PKG_SOURCE_URL:=https://fregie:fregie789632145@github.com/geewan-rd/GTS.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=c8b5d2512fd8087874a112b9a77dad837f3736df
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

define Package/GTS/install
	$(INSTALL_DIR) $(1)/etc/GTS
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client.json $(1)/etc/GTS/client.json
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client_down.sh $(1)/etc/GTS/client_down.sh
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/samples/client_up.sh $(1)/etc/GTS/client_up.sh
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/GTS-client $(1)/usr/bin
endef

$(eval $(call BuildPackage,GTS))