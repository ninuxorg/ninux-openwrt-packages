# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-brcm
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-brcm
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+ahcpd +olsrd +olsrd-mod-dot-draw +olsrd-mod-dyn-gw +olsrd-mod-httpinfo +olsrd-mod-nameservice +olsrd-mod-txtinfo +ip +libpthread +wl +horst +snmpd +tcpdump +kmod-ipv6 +avahi-daemon +avahi-dnsconfd +iputils-ping6 +iputils-traceroute6 @TARGET_brcm47xx||@TARGET_brcm_2_4||@TARGET_ar7
  TITLE:=Ninux.org Community Config Package
endef

define Package/ninux-brcm/install
	$(CP) -a ./files/* $(1)/
	$(SED) 's,$$$$R,$(REVISION),g' $(1)/etc/banner 
	$(CP) -a ./ipkg/ninux-brcm.postinst $(1)/CONTROL/postinst
	$(CP) -a ./ipkg/ninux-brcm.prerm $(1)/CONTROL/prerm
endef

define Package/ninux-brcm/description
  Prepara il router per la rete ninux.org 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-brcm))

