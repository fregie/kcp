include $(TOPDIR)/rules.mk

PKG_NAME:=GTS
# PKG_VERSION:=0.0.1
PKG_RELEASE=0.0.1

PKG_MAINTAINER:=fregie

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=net
  CATEGORY:=Network
  TITLE:=GTS-client
  DEPENDS:=+kmod-tun +ip +libsodium +libopenssl
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./samples/* $(PKG_BUILD_DIR)/
endef

define Package/$(PKG_NAME)/description
Geewan transmit system,for better experience
endef

define Package/GTS/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/GTS
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/client.json $(1)/etc/GTS/client.json
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/client_up.sh $(1)/etc/GTS/client_up.sh
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/client_down.sh $(1)/etc/GTS/client_down.sh
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/35-GTS $(1)/etc/hotplug.d/iface/35-GTS
	$(INSTALL_BIN) ./files/GTS.init $(1)/etc/init.d/GTS
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/GTS-client $(1)/usr/bin
endef

$(eval $(call BuildPackage,GTS))
