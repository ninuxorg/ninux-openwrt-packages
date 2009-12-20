
# Copyright (C) 2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=olsrd-dev
PKG_VERSION:=0.5.7-tip
PKG_RELEASE:=3

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_SOURCE:=olsrd-dev.tar.bz2
PKG_SOURCE_URL:=git://olsr.org/olsrd.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

TARGET_CFLAGS += $(FPIC)

define Package/olsrd-dev/template
  SECTION:=net
  CATEGORY:=Network
  TITLE:=OLSR unstable tip
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

define Package/olsrd-dev-mod-nameservice
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=Lightweight hostname resolver plugin
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

define Package/olsrd-dev-mod-mdns
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=MDNS/Zeroconf/Bonjour packet distribution 
endef

define Package/olsrd-dev-mod-obamp
  $(call Package/olsrd-dev/template)
  DEPENDS:=olsrd-dev
  TITLE:=OBAMP overlay multicast 
endef

define Package/olsrd-dev-mod-secure/conffiles
/etc/olsrd.d/olsrd_secure_key
endef

#define Build/Prepare
#	$(call Package/Prepare/Default) 
#	gzip -dc $(DL_DIR)/$(PKG_SOURCE) | $(HOST_TAR) -C $(PKG_BUILD_DIR)/.. $(TAR_OPTIONS)
#	echo `/bin/ls $(PKG_BUILD_DIR)/../ | egrep "olsrd\-([a-f]|[0-9]){12}"`
#	ln -s $(PKG_BUILD_DIR)/../`/bin/ls $(PKG_BUILD_DIR)/../ | /bin/egrep "olsrd\-([a-f]|[0-9]){12}"` $(PKG_BUILD_DIR)/olsr
#	echo -e "all:\n\tmake -C ./olsr all\n\nlibs:\n\tmake -C ./olsr libs\n\ninstall:\n\tmake -C ./olsr install\n\ninstall_libs:\n\tmake -C ./olsr install_libs" > $(PKG_BUILD_DIR)/Makefile
#endef 
#
#define Build/Configure
#endef

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
		SUBDIRS="arprefresh bmf dot_draw dyn_gw dyn_gw_plain httpinfo nameservice secure txtinfo mdns obamp" \
		all libs install install_libs
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

define Package/olsrd-dev-mod-nameservice/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/nameservice/olsrd_nameservice.so.* $(1)/usr/lib/
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

define Package/olsrd-dev-mod-mdns/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/mdns/olsrd_mdns.so.* $(1)/usr/lib/
endef

define Package/olsrd-dev-mod-obamp/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/obamp/olsrd_obamp.so.* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,olsrd-dev))
$(eval $(call BuildPackage,olsrd-dev-mod-arprefresh))
$(eval $(call BuildPackage,olsrd-dev-mod-dot-draw))
$(eval $(call BuildPackage,olsrd-dev-mod-bmf))
$(eval $(call BuildPackage,olsrd-dev-mod-dyn-gw))
$(eval $(call BuildPackage,olsrd-dev-mod-dyn-gw-plain))
$(eval $(call BuildPackage,olsrd-dev-mod-httpinfo))
$(eval $(call BuildPackage,olsrd-dev-mod-nameservice))
$(eval $(call BuildPackage,olsrd-dev-mod-secure))
$(eval $(call BuildPackage,olsrd-dev-mod-txtinfo))
$(eval $(call BuildPackage,olsrd-dev-mod-mdns))
$(eval $(call BuildPackage,olsrd-dev-mod-obamp))
