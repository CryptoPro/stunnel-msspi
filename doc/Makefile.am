## Process this file with automake to produce Makefile.in
# by Michal Trojnara 1998-2026

EXTRA_DIST = stunnel.md stunnel.8.in stunnel.html.in en
EXTRA_DIST += stunnel.pl.md stunnel.pl.8.in stunnel.pl.html.in pl

man_MANS = stunnel.8 stunnel.pl.8

docdir = $(datadir)/doc/stunnel
doc_DATA = stunnel.html stunnel.pl.html

CLEANFILES = $(man_MANS)
DISTCLEANFILES = $(doc_DATA)

BUILD_DATE = $(shell date --utc --date=@$(or $(SOURCE_DATE_EPOCH),$(shell date +%s)) +%Y.%m.%d)

SUFFIXES = .md .8.in .html.in

.md.8.in:
	pandoc -s -t man \
		-M title='STUNNEL' \
		-V section='8' \
		-V header='stunnel TLS Proxy' \
		-V footer='stunnel $(VERSION)' \
		-V date='$(BUILD_DATE)' \
		-o $@ $<

.md.html.in:
	pandoc -s -t html --toc \
		-M title='stunnel TLS Proxy' \
		-V maxwidth=72em \
		-o $@ $<

edit_man = sed \
	-e 's|\\\[at\]bindir\\\[at\]|$(bindir)|g' \
	-e 's|\\\[at\]sysconfdir\\\[at\]|$(sysconfdir)|g'

edit_html = sed \
	-e 's|@bindir[@]|<i>\&lt;bin-folder\&gt;<\/i>|g' \
	-e 's|@sysconfdir[@]/stunnel|<i>\&lt;config-folder\&gt;<\/i>|g'

$(man_MANS): Makefile
	$(edit_man) '$(srcdir)/$@.in' >$@

$(doc_DATA): Makefile
	$(edit_html) '$(srcdir)/$@.in' >$@

stunnel.8: $(srcdir)/stunnel.8.in
stunnel.html: $(srcdir)/stunnel.html.in
stunnel.pl.8: $(srcdir)/stunnel.pl.8.in
stunnel.pl.html: $(srcdir)/stunnel.pl.html.in
