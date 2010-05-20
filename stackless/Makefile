# 
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
#

include $(TOPDIR)/rules.mk

PKG_NAME:=stackless
PKG_VERSION:=2.6.2

PKG_SOURCE:=$(PKG_NAME)-262-export.tar.bz2
PKG_SOURCE_URL:=http://www.stackless.com/binaries/
PKG_MD5SUM:=cad498a856135ea2cef7407066b19304
PKG_BUILD_DIR:=$(BUILD_DIR)/python-$(PKG_VERSION)-$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/stackless
  SECTION:=lang
  CATEGORY:=Languages
  DEPENDS:=+libpthread
  TITLE:=stackless python
  URL:=http://www.stackless.com/
endef

define Package/stackless/description
   Stackless Python is an enhanced version of the Python programming language.
   It allows programmers to reap the benefits of thread-based programming without 
   the performance and complexity problems associated with conventional threads.
endef

CONFIGURE_ARGS += \
	--enable-static \
	--enable-shared

CONFIGURE_VARS += \
	CXXFLAGS="$$$$CXXFLAGS -fno-builtin -fno-rtti -nostdinc++"  \
	CPPFLAGS="$$$$CPPFLAGS -I$(STAGING_DIR)/usr/include/uClibc++ -I$(LINUX_DIR)/include" \
	LDFLAGS="$$$$LDFLAGS" 

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CFLAGS="$(TARGET_CFLAGS)" \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		python
endef


define Build/InstallDev
	mkdir -p $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/Include/*.h $(1)/usr/include/
	mkdir -p $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libpython2.6.{a,so*} $(1)/usr/lib/
endef

define Build/UninstallDev
	rm -rf	$(1)/usr/include/ \
		$(1)/usr/include/libpython2.6.{a,so*}
endef

define Package/stackless/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libpython2.6.{a,so*}  $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/python  $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib/python2.6/
	$(CP) $(PKG_BUILD_DIR)/Lib/*.py $(1)/usr/lib/python2.6/
endef

$(eval $(call BuildPackage,stackless))
