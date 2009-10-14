# 
# Copyright (C) 2007 Ninux.org <contatti@ninux.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=ninux-x86
PKG_VERSION:=0.1
PKG_RELEASE:=alpha

# PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# PKG_SOURCE_URL:=http://
# PKG_MD5SUM:=
# PKG_CAT:=zcat
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/ninux-x86
  SECTION:=admin
  CATEGORY:=Administration
  DEPENDS:=+ahcpd +olsrd-ninux +olsrd-ninux-mod-mdns +olsrd-ninux-mod-dot-draw +olsrd-ninux-mod-dyn-gw +olsrd-ninux-mod-httpinfo +olsrd-ninux-mod-nameservice +olsrd-ninux-mod-txtinfo +ip +libpthread +wl +horst +snmpd +tcpdump +kmod-ipv6 +avahi-daemon +avahi-dnsconfd +iputils-ping6 +iputils-traceroute6 +wireless-tools +olsrd-ninux-mod-bmf +olsrd-ninux-mod-secure +kmod-madwifi +openvpn +kmod-ipt-extra +kmod-ipt-conntrack +kmod-ipt-nathelper +kmod-ipt-nathelper-extra @TARGET_x86
  TITLE:=Ninux.org Community Config Package
endef

define Package/ninux-x86/install
	$(CP) -a ./files/* $(1)/
	$(SED) 's,$$$$R,$(REVISION),g' $(1)/etc/banner
	$(CP) -a ./ipkg/ninux-x86.postinst $(1)/CONTROL/postinst
	$(CP) -a ./ipkg/ninux-x86.prerm $(1)/CONTROL/prerm
endef

define Package/ninux-x86/description
  Prepara il router per la rete ninux.org 
endef

define Build/Compile
endef

$(eval $(call BuildPackage,ninux-x86))

