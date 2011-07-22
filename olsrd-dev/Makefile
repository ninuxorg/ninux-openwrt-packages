# 
# Copyright (C) 2008-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id $

include $(TOPDIR)/rules.mk

PKG_NAME:=olsrd-dev
PKG_VERSION:=0.6.999-master
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_SOURCE:=olsrd-dev.tar.bz2
PKG_SOURCE_URL:=git://olsr.org/olsrd.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += $(FPIC)

define Package/olsrd-dev/template
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=OLSR unstable tip
  MAINTAINER:=contatti@ninux.org
  URL:=http://www.olsr.org/
endef

define Package/olsrd-dev
  $(call Package/olsrd-dev/template)
  MENU:=1
  DEPENDS:=+libpthread
endef

define Package/olsrd-dev/conffiles
/etc/config/olsrd
endef

define Package/olsrd-dev-mod-arprefresh
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Kernel ARP cache refresh plugin
endef

define Package/olsrd-dev-mod-dot-draw
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Dot topology information plugin
endef

define Package/olsrd-dev-mod-bmf
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev +kmod-tun
  TITLE:=Basic multicast forwarding plugin
endef

define Package/olsrd-dev-mod-dyn-gw
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Dynamic internet gateway plugin
endef

define Package/olsrd-dev-mod-dyn-gw-plain
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Dynamic internet gateway plain plugin
endef

define Package/olsrd-dev-mod-httpinfo
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Small informative web server plugin
endef

define Package/olsrd-dev-mod-mdns
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=MDNS/Zeroconf/Bonjour packet distribution 
endef

define Package/olsrd-dev-mod-nameservice
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Lightweight hostname resolver plugin
endef

define Package/olsrd-dev-mod-quagga
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Quagga plugin
endef

define Package/olsrd-dev-mod-secure
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Message signing plugin to secure routing domain
endef

define Package/olsrd-dev-mod-txtinfo
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Small informative web server plugin
endef

define Package/olsrd-dev-mod-watchdog
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Watchdog plugin
endef

define Package/olsrd-dev-mod-obamp
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=OBAMP overlay multicast 
endef

define Package/olsrd-dev-mod-cl_roam
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=CL Roam Plugin
endef

define Package/olsrd-dev-mod-secure/conffiles
/etc/olsrd.d/olsrd_secure_key
endef

MAKE_FLAGS+= \
	NO_DEBUG_MESSAGES=1 \
	OS="linux" \
	DESTDIR="$(PKG_INSTALL_DIR)" \
	STRIP="true" \
	INSTALL_LIB="true" \
	SUBDIRS="arprefresh bmf cl_roam dot_draw dyn_gw dyn_gw_plain httpinfo mdns nameservice obamp quagga secure txtinfo watchdog"
define Build/Compile
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(call Build/Compile/Default,all)
	$(call Build/Compile/Default,libs)
endef

define Build/Install
	$(call Build/Install/Default,install)
	$(call Build/Install/Default,install_libs)
endef
define Package/olsrd-dev/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/olsrd.config $(1)/etc/config/olsrd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/olsrd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/olsrd.init $(1)/etc/init.d/olsrd
endef

define Package/olsrd-dev-mod-arprefresh/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/arprefresh/olsrd_arprefresh.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-dot-draw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dot_draw/olsrd_dot_draw.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-bmf/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/bmf/olsrd_bmf.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-dyn-gw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw/olsrd_dyn_gw.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-dyn-gw-plain/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw_plain/olsrd_dyn_gw_plain.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-httpinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/httpinfo/olsrd_httpinfo.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-mdns/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/mdns/olsrd_mdns.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-nameservice/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/nameservice/olsrd_nameservice.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-quagga/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/quagga/olsrd_quagga.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-secure/install
	$(INSTALL_DIR) $(1)/etc/olsrd.d
	$(CP) ./files/olsrd_secure_key $(1)/etc/olsrd.d/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/secure/olsrd_secure.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-txtinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/txtinfo/olsrd_txtinfo.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-watchdog/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/watchdog/olsrd_watchdog.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-obamp/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/obamp/olsrd_obamp.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-cl_roam/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/cl_roam/olsrd_cl_roam.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,olsrd-dev))
$(eval $(call BuildPackage,olsrd-dev-mod-arprefresh))
$(eval $(call BuildPackage,olsrd-dev-mod-dot-draw))
$(eval $(call BuildPackage,olsrd-dev-mod-bmf))
$(eval $(call BuildPackage,olsrd-dev-mod-dyn-gw))
$(eval $(call BuildPackage,olsrd-dev-mod-dyn-gw-plain))
$(eval $(call BuildPackage,olsrd-dev-mod-httpinfo))
$(eval $(call BuildPackage,olsrd-dev-mod-mdns))
$(eval $(call BuildPackage,olsrd-dev-mod-nameservice))
$(eval $(call BuildPackage,olsrd-dev-mod-quagga))
$(eval $(call BuildPackage,olsrd-dev-mod-secure))
$(eval $(call BuildPackage,olsrd-dev-mod-txtinfo))
$(eval $(call BuildPackage,olsrd-dev-mod-obamp))
$(eval $(call BuildPackage,olsrd-dev-mod-cl_roam))

