#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=vlc
PKG_VERSION:=1.1.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://download.videolan.org/pub/videolan/vlc/$(PKG_VERSION)/$(PKG_SOURCE)
PKG_MD5SUM:=e2142957137b183a5ad0a4827c39f655

include $(INCLUDE_DIR)/package.mk

define Package/vlc
   SECTION:=Multimedia
   CATEGORY:=Media
   TITLE:=Videolan Client
   DEPENDS:=+libflac +libid3tag +libmad +libvorbisidec +libffmpeg +libiconv +libpthread +libvorbis
   URL:=http://www.videolan.org/
endef

define Package/vlc/description
   VideoLAN: Free Multimedia Solutions
endef

define Package/vlc-http
   SECTION:=Multimedia
   CATEGORY:=Media
   TITLE:=Videolan Client
   DEPENDS:=+vlc
   URL:=http://www.videolan.org/
endef

define Package/vlc/description
   VideoLAN: the http interface
endef
define Build/Configure
	$(call Build/Configure/Default, \
	 --with-linux-headers="$(LINUX_DIR)" \
	 --enable-run-as-root \
	 --disable-a52 \
	 --disable-dbus \
	 --disable-dbus-control \
	 --disable-vlm \
	 --disable-notify \
	 --disable-audioscrobbler \
	 --disable-live555 \
	 --disable-dvdnav \
	 --disable-dshow \
	 --disable-bda \
	 --disable-smb \
	 --disable-dvbpsi \
	 --disable-libv4l2 \
	 --disable-libcdio \
	 --disable-libvcdinfo \
	 --disable-libcddb \
	 --disable-cdda \
	 --disable-vcd \
	 --disable-dvb \
	 --disable-screen \
	 --disable-mkv \
	 --disable-mod \
	 --disable-gme \
	 --disable-postproc \
	 --disable-quicktime \
	 --disable-libtar \
	 --disable-a52 \
	 --disable-speex \
	 --disable-schroedinger \
	 --disable-png \
	 --disable-x264 \
	 --disable-fluidsynth \
	 --disable-cmml \
	 --disable-kate \
	 --disable-x11 \
	 --disable-xvideo \
	 --disable-glx \
	 --disable-xinerama \
	 --disable-opengl \
	 --disable-sdl \
	 --disable-sdl-image \
	 --disable-freetype \
	 --disable-fribidi \
	 --disable-fontconfig \
	 --disable-libxml2 \
	 --disable-hd1000v \
	 --disable-directx \
	 --disable-fb \
	 --disable-wingdi \
	 --disable-pulse \
	 --disable-waveout \
	 --disable-macosx-audio \
	 --disable-hd1000a \
	 --disable-upnp \
	 --disable-skins2 \
	 --disable-qt4 \
	 --disable-wince \
	 --disable-macosx \
	 --disable-visual \
	 --disable-bonjour \
	 --disable-libgcrypt \
	 --disable-gnutls \
	 --disable-remoteosd \
	 --disable-activex \
	 --disable-nls \
	 --disable-rpath \
	 --disable-telepathy \
	 --disable-cddax \
	 --disable-swscale \
	 --disable-dca \
	 --disable-telx \
	 --disable-zvbi \
	 --disable-atmo \
	 --disable-mozilla \
	 --disable-xcb \
	 --enable-optimize-memory \
	 --with-libiconv-prefix=$(STAGING_DIR)/usr/lib/libiconv \
	 CFLAGS="$(CFLAGS) -std=gnu99" \
	)
endef

define Package/vlc/install
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR="$(1)" install
	rm -rf "$(1)"/usr/include
	rm -f  "$(1)"/usr/lib/vlc/*/*.la
	rm -rf "$(1)"/usr/share/applications
	rm -rf "$(1)"/usr/share/doc
	rm -rf "$(1)"/usr/share/vlc/*.png
	rm -rf "$(1)"/usr/share/vlc/*.xpm
	rm -rf "$(1)"/usr/share/vlc/*.ico
endef

define Package/vlc-http/install
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR="$(1)" install
	rm -rf "$(1)"/usr/include
	rm -f  "$(1)"/usr/lib/vlc/*/*.la
	rm -rf "$(1)"/usr/share/applications
	rm -rf "$(1)"/usr/share/doc
	rm -rf "$(1)"/usr/share/vlc/*.png
	rm -rf "$(1)"/usr/share/vlc/*.xpm
	rm -rf "$(1)"/usr/share/vlc/*.ico
endef

$(eval $(call BuildPackage,vlc))
#$(eval $(call BuildPackage,vlc-http))

