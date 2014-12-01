# Maintainer: Anton Batenev <antonbatenev@yandex.ru>

pkgname=ydcmd
pkgver=0.7
pkgrel=1
pkgdesc='Command line client for Yandex.Disk'
arch=('any')
url='https://github.com/abbat/ydcmd'
license=('BSD')
depends=('python2>=2.6' 'python2-dateutil')
makedepends=('python2>=2.6' 'git')
optdepends=('ca-certificates: ssl certificates validation')
source=('git+https://github.com/abbat/ydcmd.git')
sha256sums=('SKIP')

package() {
	install -d ${pkgdir}/usr/bin
	install -D -m755 ${srcdir}/${pkgname}/ydcmd.py         ${pkgdir}/usr/lib/python2.7/${pkgname}.py
	install -D -m644 ${srcdir}/${pkgname}/man/ydcmd.1      ${pkgdir}/usr/share/man/man1/${pkgname}.1
	install -D -m644 ${srcdir}/${pkgname}/man/ydcmd.ru.1   ${pkgdir}/usr/share/man/ru/man1/${pkgname}.1
	install -D -m644 ${srcdir}/${pkgname}/README.md        ${pkgdir}/usr/share/doc/${pkgname}/README.md
	install -D -m644 ${srcdir}/${pkgname}/README.en.md     ${pkgdir}/usr/share/doc/${pkgname}/README.en.md
	install -D -m644 ${srcdir}/${pkgname}/ydcmd.cfg        ${pkgdir}/usr/share/doc/${pkgname}/${pkgname}.cfg
	install -D -m644 ${srcdir}/${pkgname}/debian/copyright ${pkgdir}/usr/share/licenses/${pkgname}/LICENSE

	sed -i -e 's/^#!\/usr\/bin\/env python$/#!\/usr\/bin\/env python2/g' ${pkgdir}/usr/lib/python2.7/${pkgname}.py
	/usr/bin/env python2 -m compileall ${pkgdir}/usr/lib/python2.7/${pkgname}.py

	ln -s /usr/lib/python2.7/${pkgname}.py ${pkgdir}/usr/bin/${pkgname}
}
