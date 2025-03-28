include ../global.mk
include config.mk
include ../config-user.mk
include ../mk/platform.mk
include ../mk/${COMPILER}.mk
include ${SHLR}/zip/deps.mk

DESTDIR:=$(DESTDIR)
PREFIX?=${PWD}/../prefix
OBJCOPY?=objcopy

S=$
B=`
PWD=$(shell pwd)

include libs.mk

.PHONY: $(LIBS)

all:
ifneq ($(LIBS0),)
	$(MAKE) $(LIBS0)
endif
ifneq ($(LIBS1),)
	$(MAKE) $(LIBS1)
endif
ifneq ($(LIBS2),)
	$(MAKE) $(LIBS2)
endif
ifneq ($(LIBS3),)
	$(MAKE) $(LIBS3)
endif
ifneq ($(LIBS4),)
	$(MAKE) $(LIBS4)
endif
ifneq ($(LIBS5),)
	$(MAKE) $(LIBS5)
endif
ifneq ($(LIBS6),)
	$(MAKE) $(LIBS6)
endif
ifneq ($(LIBS7),)
	$(MAKE) $(LIBS7)
endif
ifneq ($(LIBS8),)
	$(MAKE) $(LIBS8)
endif
ifeq ($(WITH_LIBR),1)
	$(MAKE) libr.${EXT_AR}
	$(MAKE) libr.${EXT_SO}
endif

ifeq ($(WITH_LIBR),1)

ifeq ($(CC),emcc)
MLFLAGS=
else
ifeq ($(OSTYPE),darwin)
MLFLAGS+=-install_name @rpath/libr2.dylib
endif
ifeq ($(OSTYPE),ios)
MLFLAGS+=-install_name @rpath/libr2.dylib
MLFLAGS+=-fembed-bitcode
endif
endif
LDFLAGS+=${SSL_LDFLAGS}
# XXX version-script only works with shlib as output
#ifeq ($(OSTYPE),linux)
#PLFLAGS+=--version-script ./ld.script
#endif
# from env: ALFLAGS+=$(ALFLAGS)

localize_hidden:
	for LIB in .libr/* ; do $(OBJCOPY) --localize-hidden $$LIB ; done

# ${PARTIALLD} $(ALFLAGS) $(MLFLAGS) $(PLFLAGS) -o .libr/$$(basename $${LIB}.a).o $${LIB}
.libr: $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}
	rm -rf .libr
	mkdir -p .libr
	for LIB in $^ ; do \
		${PARTIALLD} $(ALFLAGS) $(MLFLAGS) $(PLFLAGS) -o .libr/$$(basename $${LIB}.a).o $${LIB} ; \
	done
ifeq ($(OSTYPE),linux)
	$(MAKE) localize_hidden
endif
ifeq ($(OSTYPE),gnulinux)
	$(MAKE) localize_hidden
endif
ifeq ($(OSTYPE),android)
	$(MAKE) localize_hidden
endif
ifeq ($(OSTYPE),bsd)
	$(MAKE) localize_hidden
endif

_libr.${EXT_AR}: .libr
	-${AR} -rs $@ .libr/*.o

# this code should be in do-ar-sh not inlined here..

.libr2: $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}
	rm -rf .libr2
	mkdir -p .libr2
	-for LIB in $^ ; do \
		BN=`basename $$LIB` ; \
		mkdir -p .libr2/$$BN ; \
		echo "( cd .libr2/$$BN ; pwd ; du -hs ../../$$LIB; ${AR} -x ../../$$LIB )" ; \
		( cd .libr2/$$BN ; pwd ; du -hs ../../$$LIB; ${AR} -x ../../$$LIB ) ; \
	done

libr.${EXT_AR}: .libr2
	-${AR} -rs $@ .libr2/*/*.o

ifeq (1,$(WITH_GPL))
E+=../shlr/grub/libgrubfs.${EXT_AR}
endif
E+=../shlr/ar/libr_ar.${EXT_AR}
E+=../shlr/winkd/libr_winkd.${EXT_AR}
E+=../shlr/qnx/lib/libqnxr.${EXT_AR}
E+=../shlr/bochs/lib/libbochs.${EXT_AR}
E+=../libr/asm/arch/arm/v35arm64/arm64dis.${EXT_AR}
E+=../libr/asm/arch/arm/v35arm64/armv7dis.${EXT_AR}

ifeq ($(USE_CAPSTONE),1)
E+=$(CAPSTONE_LDFLAGS)
else
E+=../shlr/capstone/libcapstone.${EXT_AR}
endif

ifeq ($(OSTYPE),darwin)
LIBR_LDFLAGS=-dynamiclib -shared
else
LIBR_LDFLAGS=-shared
endif

libr.${EXT_SO}: .libr2
ifeq (${COMPILER},emscripten)
	echo nothing to do here
else
	$(CC) -fvisibility=hidden $(MLFLAGS) ${LINK} ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} $(LIBR_LDFLAGS) -o libr.${EXT_SO}  \
		.libr2/*/*.o \
		../shlr/gdb/lib/libgdbr.${EXT_AR} ../shlr/java/libr_java.${EXT_AR} \
		../shlr/libr_shlr.${EXT_AR} ../shlr/mpc/libmpc.${EXT_AR} $(E) \
		../libr/util/libr_util.${EXT_AR}
endif

else

# WITH_LIBR=0

libr.${EXT_SO}:
	$(MAKE) libr.${EXT_SO} WITH_LIBR=1

libr.${EXT_AR}:
	$(MAKE) libr.${EXT_AR} WITH_LIBR=1
endif

../shlr/libr_shlr.${EXT_AR}:
	$(MAKE) -C ../shlr libr_shlr.${EXT_AR}

$(LIBS):
	@echo "DIR $@"
	@$(MAKE) -C $@

pkgcfg:
	@for lib in ${LIBS}; do $(MAKE) -C $${lib} pkgcfg; done
	$(MAKE) -C asm pkgcfg NAME=libr R2DEPS="r_`echo ${LIBS}|sed -e 's, , r_,g'`"
	# TODO: Magically generate libr.pc.acr here using LIBS and so :)

install-pkgconfig:
	${INSTALL_DIR} "${DESTDIR}${LIBDIR}/pkgconfig"
	for FILE in ../pkgcfg/*.pc ; do \
		rm -f "${DESTDIR}${LIBDIR}/pkgconfig/$$FILE" ; \
		${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}/pkgconfig" ; done

install-includes:
	@-rm -f "${DESTDIR}${INCLUDEDIR}/libr/sflib"
	@-rm -f "${DESTDIR}${INCLUDEDIR}/libr"
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr"
	(cd include && for FILE in *.h ; do ${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr" ; done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib"
	(cd include/sflib && for DIR in * ; do \
		${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$DIR" ; \
		for FILE in $$DIR/*.h ; do \
			${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/sflib/$$FILE" ; \
		done ; \
	done)
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/sdb"
	(cd ../shlr/sdb/src && for FILE in *.h ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/sdb/$$FILE" ; \
	done)
	for a in r_util r_crypto r_anal ; do \
	${INSTALL_DIR} "${DESTDIR}${INCLUDEDIR}/libr/$$a" ; \
	(cd include/$$a && for FILE in * ; do \
		${INSTALL_DATA} $$FILE "${DESTDIR}${INCLUDEDIR}/libr/$$a/$$FILE" ; done) ; \
	done

symstall install-symlink:
	@cd .. && \
	mkdir -p "${DESTDIR}${BINDIR}" \
		"${DESTDIR}${INCLUDEDIR}" \
		"${DESTDIR}${LIBDIR}/pkgconfig" \
		"${DESTDIR}${LIBDIR}/radare2/${VERSION}" ; \
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr" && ln -fs "${PWD}/include" "${DESTDIR}${INCLUDEDIR}/libr" ; \
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr/sdb" && ln -fs "${PWD}/../shlr/sdb/src" "${DESTDIR}${INCLUDEDIR}/libr/sdb" ; \
	$(MAKE) install-pkgconfig-symlink ; \
	$(foreach lib,${LIBS}, \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/libr_$(lib).${EXT_SO}" ; \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/$(call libname-version,libr_$(lib).${EXT_SO},${LIBVERSION})" ; \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_SO}" \
		"${DESTDIR}${LIBDIR}/$(call libname-version,libr_$(lib).${EXT_SO},${ABIVERSION})" ; \
	  ln -fs "${PWD}/$(lib)/libr_$(lib).${EXT_AR}" "${DESTDIR}${LIBDIR}/libr_$(lib).${EXT_AR}" ; \
	  $(foreach module,$(wildcard $(lib)/p/*.${EXT_SO}), \
	    ln -fs "${PWD}/$(module)" "${DESTDIR}${LIBDIR}/radare2/${VERSION}/" ; \
	  ) \
	) \
	cd "${DESTDIR}${LIBDIR}/radare2" ; rm -f last ; ln -fs "${VERSION}" last

install: install-includes install-pkgconfig
	# TODO :Use INSTALL_DATA_DIR instead of mkdir
	# libraries
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}"
	@$(foreach lib,$(shell find * -type f -iname "*.${EXT_SO}" | grep -vE '^libr\.${EXT_SO}$$' | grep -v '(lib|parse)/t/' | grep lib | grep -v /bin/ | grep -v /p/), \
	  echo " ${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION}) -> $(call libpath-to-name-version,$(lib),${ABIVERSION}) -> $(lib)"; \
	  rm -f "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  rm -f "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${ABIVERSION})"; \
	  ${INSTALL_LIB} "$(lib)" "${DESTDIR}${LIBDIR}/$(call libpath-to-name-version,$(lib),${LIBVERSION})"; \
	  ( cd "${DESTDIR}${LIBDIR}" ; ln -fs "$(call libpath-to-name-version,$(lib),${LIBVERSION})" "$(call libpath-to-name-version,$(lib),${ABIVERSION})" ) ; \
	  ( cd "${DESTDIR}${LIBDIR}" ; ln -fs "$(call libpath-to-name-version,$(lib),${ABIVERSION})" "$(call libpath-to-name,$(lib))" ) ; \
	)
	lib=libr.$(EXT_SO) ; if [ -f "$$lib" ]; then \
	  ${INSTALL_LIB} "$$lib" "${DESTDIR}${LIBDIR}/$$lib"; \
	fi
	# object archives
	@for FILE in `find * -type f -iname "*.${EXT_AR}" | grep -v fs/p` ; do \
	  echo " ${DESTDIR}${LIBDIR}/$$FILE"; ${INSTALL_DATA} $$FILE "${DESTDIR}${LIBDIR}" ; done || true
	# plugins
	@${INSTALL_DIR} "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	@for FILE in `find */p -perm -u+x -type f | grep -v exe | grep -v dll | grep ${EXT_SO}`; \
	  do echo " ${DESTDIR}${LIBDIR}/radare2/${VERSION}/$$FILE"; \
	  ${INSTALL_LIB} "$$FILE" "${DESTDIR}${LIBDIR}/radare2/${VERSION}" ; done
	cd "${DESTDIR}${LIBDIR}/radare2" ; ln -fs "${VERSION}" last

deinstall uninstall:
	# libraries
	-@for FILE in `find * | grep -e '\.${EXT_SO}$$' | grep -v 'lib/t' | grep lib` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# object archives
	-@for FILE in `find * | grep -e '\.${EXT_AR}$$'` ; do \
	FILE=`echo $$FILE | awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${LIBDIR}/$$FILE" ; rm -f "${DESTDIR}${LIBDIR}/$$FILE" ; done
	# includes
	-if [ -h "${DESTDIR}${INCLUDEDIR}/libr" ]; then \
		rm -f "${DESTDIR}${INCLUDEDIR}/libr" ; \
	else \
		(cd include && for FILE in * ; do rm -f "${DESTDIR}${INCLUDEDIR}/libr/$$FILE" ; done) ; \
	fi
	# programs
	-@for FILE in `find */t -perm -u+x -type f | grep 2`; do \
	FILE=`echo $$FILE|awk -F / '{ print $$NF; }'`; \
	echo "${DESTDIR}${BINDIR}/$$FILE" ; rm -f "${DESTDIR}${BINDIR}/$$FILE" ; done
	# plugins
	-@for FILE in `find */p -perm -u+x -type f`; do \
	FILE="${DESTDIR}${LIBDIR}/radare2/${VERSION}/`echo $$FILE|awk -F / '{ print $$NF; }'`"; \
	echo $$FILE ; rm -f $$FILE ; done
	rm -rf "${DESTDIR}${LIBDIR}/radare2/${VERSION}"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/libr.pc"
	rm -f "${DESTDIR}${LIBDIR}/pkgconfig/r_"*.pc
	# test programs
	rm -rf "${DESTDIR}${BINDIR}/libr-test"
	# TODO: use for FILE in LIBS (like in binr/Makefile)
	rm -rf "${DESTDIR}${INCLUDEDIR}/libr"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.${LIBVERSION}"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.${ABIVERSION}"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so.0"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.so"
	rm -rf "${DESTDIR}${LIBDIR}/libr_*.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/libr2.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr2.${EXT_AR}"
	rm -rf "${DESTDIR}${LIBDIR}/libr.so"*
	rm -rf "${DESTDIR}${LIBDIR}/libr.${EXT_AR}"
	rm -rf "${DESTDIR}${DATADIR}/doc/radare2"
	@echo libr aka radare2 has been uninstalled from PREFIX=${DESTDIR}${PREFIX}

clean:
	for LIB in ${LIBS}; do ( cd $${LIB} && $(MAKE) clean ); done
	rm -rf .libr libr.${LIB_SO} libr.${LIB_AR}

mrproper:
	rm -rf .libr libr.${LIB_SO} libr.${LIB_AR}
	for LIB in ${LIBS}; do ( cd $${LIB} && $(MAKE) mrproper ); done

.PHONY: sloc mrproper clean pkgcfg install deinstall uninstall libr
.PHONY: install-includes install-pkgconfig install-symlink all
