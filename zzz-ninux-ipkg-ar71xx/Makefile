# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-ar71xx
PKG_VERSION:=0.1
PKG_RELEASE:=beta

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-ar71xx
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+kmod-ipv6 +ahcpd +avahi-daemon +avahi-dnsconfd +iputils-ping6 +iputils-traceroute6 +webif +webif-lang-it +olsrd-ninux +olsrd-ninux-mod-dot-draw +olsrd-ninux-mod-dyn-gw +olsrd-ninux-mod-httpinfo +olsrd-ninux-mod-nameservice +olsrd-ninux-mod-txtinfo +olsrd-ninux-mod-mdns +olsrd-ninux-mod-arprefresh +ip +libpthread +horst +snmpd +tcpdump @TARGET_ar71xx
  TITLE:=Ninux.org Community Config Package
endef

define Package/ninux-ar71xx/install
	$(CP) -a ./files/* $(1)/
	$(SED) 's,$$$$R,$(REVISION),g' $(1)/etc/banner 
	mkdir -p $(1)/CONTROL
	$(CP) -a ./ipkg/ninux-ar71xx.postinst $(1)/CONTROL/postinst
	$(CP) -a ./ipkg/ninux-ar71xx.prerm $(1)/CONTROL/prerm
endef

define Package/ninux-ar71xx/description
  Prepara il router per la rete ninux.org 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-ar71xx))

