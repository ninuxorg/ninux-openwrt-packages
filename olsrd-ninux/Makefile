# 
# Copyright (C) 2008-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id $

include $(TOPDIR)/rules.mk

PKG_NAME:=olsrd-ninux
PKG_VERSION:=0.5.6-r7
PKG_RELEASE:=2

PKG_BUILD_DIR:=$(BUILD_DIR)/olsrd-ninux-$(PKG_VERSION)/
PKG_SOURCE:=olsrd-ninux-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=git://olsr.org/olsrd.git
PKG_SOURCE_VERSION:=origin/stable
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += $(FPIC)

define Package/olsrd-ninux/template
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OLSR daemon by Ninux
  MAINTAINER:=contatti@ninux.org
  URL:=http://www.olsr.org/
endef

define Package/olsrd-ninux
  $(call Package/olsrd-ninux/template)
  MENU:=1
  DEPENDS:=+libpthread
endef

define Package/olsrd-ninux/conffiles
/etc/config/olsrd
endef

define Package/olsrd-ninux-mod-arprefresh
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Kernel ARP cache refresh plugin
endef

define Package/olsrd-ninux-mod-dot-draw
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Dot topology information plugin
endef

define Package/olsrd-ninux-mod-bmf
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux +kmod-tun
  TITLE:=Basic multicast forwarding plugin
endef

define Package/olsrd-ninux-mod-dyn-gw
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Dynamic internet gateway plugin
endef

define Package/olsrd-ninux-mod-dyn-gw-plain
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Dynamic internet gateway plain plugin
endef

define Package/olsrd-ninux-mod-httpinfo
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Small informative web server plugin
endef

define Package/olsrd-ninux-mod-nameservice
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Lightweight hostname resolver plugin
endef

define Package/olsrd-ninux-mod-secure
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Message signing plugin to secure routing domain
endef

define Package/olsrd-ninux-mod-txtinfo
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=Small informative web server plugin
endef

define Package/olsrd-ninux-mod-mdns
  $(call Package/olsrd-ninux/template)
  DEPENDS:=olsrd-ninux
  TITLE:=MDNS/Zeroconf/Bonjour packet distribution 
endef

define Package/olsrd-ninux-mod-all
  $(call Package/olsrd-ninux/template)
  DEPENDS:=+olsrd-ninux +olsrd-ninux-mod-arprefresh +olsrd-ninux-mod-dot-draw +olsrd-ninux-mod-bmf +olsrd-ninux-mod-dyn-gw +olsrd-ninux-mod-dyn-gw-plain +olsrd-ninux-mod-httpinfo +olsrd-ninux-mod-nameservice +olsrd-ninux-mod-secure +olsrd-ninux-mod-txtinfo +olsrd-ninux-mod-mdns
  TITLE+= (Meta package)
endef

define Package/olsrd-ninux-mod-secure/conffiles
/etc/olsrd.d/olsrd_secure_key
endef

define Build/Configure
endef

define Build/Compile
	rm -rf $(PKG_INSTALL_DIR)
	mkdir -p $(PKG_INSTALL_DIR)
	$(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(TARGET_CONFIGURE_OPTS) \
		NODEBUG=1 \
		CFLAGS="$(TARGET_CFLAGS)" \
		OS="linux" \
		INSTALL_PREFIX="$(PKG_INSTALL_DIR)" \
		LIBDIR="$(PKG_INSTALL_DIR)/usr/lib" \
		SBINDIR="$(PKG_INSTALL_DIR)/usr/sbin/" \
		ETCDIR="$(PKG_INSTALL_DIR)/etc" \
		MANDIR="$(PKG_INSTALL_DIR)/usr/share/man" \
		STRIP="true" \
		INSTALL_LIB="true" \
		SUBDIRS="arprefresh bmf dot_draw dyn_gw dyn_gw_plain httpinfo nameservice secure txtinfo mdns" \
		all libs install install_libs
endef

define Package/olsrd-ninux/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/olsrd.config $(1)/etc/config/olsrd
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/olsrd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/olsrd.init $(1)/etc/init.d/olsrd
endef

define Package/olsrd-ninux-mod-arprefresh/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/arprefresh/olsrd_arprefresh.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-dot-draw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dot_draw/olsrd_dot_draw.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-bmf/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/bmf/olsrd_bmf.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-dyn-gw/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw/olsrd_dyn_gw.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-dyn-gw-plain/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/dyn_gw_plain/olsrd_dyn_gw_plain.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-httpinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/httpinfo/olsrd_httpinfo.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-nameservice/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/nameservice/olsrd_nameservice.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-secure/install
	$(INSTALL_DIR) $(1)/etc/olsrd.d
	$(CP) ./files/olsrd_secure_key $(1)/etc/olsrd.d/
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/secure/olsrd_secure.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-txtinfo/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/txtinfo/olsrd_txtinfo.so.* $(1)/usr/lib/
endef

define Package/olsrd-ninux-mod-mdns/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/mdns/olsrd_mdns.so.* $(1)/usr/lib/
endef
$(eval $(call BuildPackage,olsrd-ninux))
$(eval $(call BuildPackage,olsrd-ninux-mod-arprefresh))
$(eval $(call BuildPackage,olsrd-ninux-mod-dot-draw))
$(eval $(call BuildPackage,olsrd-ninux-mod-bmf))
$(eval $(call BuildPackage,olsrd-ninux-mod-dyn-gw))
$(eval $(call BuildPackage,olsrd-ninux-mod-dyn-gw-plain))
$(eval $(call BuildPackage,olsrd-ninux-mod-httpinfo))
$(eval $(call BuildPackage,olsrd-ninux-mod-nameservice))
$(eval $(call BuildPackage,olsrd-ninux-mod-secure))
$(eval $(call BuildPackage,olsrd-ninux-mod-txtinfo))
$(eval $(call BuildPackage,olsrd-ninux-mod-mdns))
$(eval $(call BuildPackage,olsrd-ninux-mod-all))
