Name:          ydcmd
Version:       2.10
Release:       1
BuildArch:     noarch
Summary:       Command line Yandex.Disk client
Group:         Applications/Internet
License:       BSD-2-Clause
URL:           https://github.com/abbat/ydcmd
Requires:      python >= 2.6, python-dateutil
BuildRequires: python-devel >= 2.6

%if 0%{?suse_version}
BuildRequires: fdupes
%endif

%if 0%{?suse_version} > 1000 || 0%{?fedora} > 20
Suggests: python-progressbar
Recommends: ca-certificates
%endif

Source0:       https://build.opensuse.org/source/home:antonbatenev:ydcmd/ydcmd/ydcmd_%{version}.tar.bz2
BuildRoot:     %{_tmppath}/%{name}-%{version}-build


%description
Command-line tool to upload, retrieve and manage data in Yandex.Disk service
(https://disk.yandex.com), designed for use in scripts.


%prep
%setup -q -n ydcmd


%build


%install

install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{python_sitelib}

install -m755 ydcmd.py %{buildroot}%{python_sitelib}/ydcmd.py

ln -s %{python_sitelib}/ydcmd.py %{buildroot}%{_bindir}/ydcmd

install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_mandir}/ru/man1
install -d %{buildroot}%{_mandir}/tr/man1

install -m644 man/ydcmd.1    %{buildroot}%{_mandir}/man1/ydcmd.1
install -m644 man/ydcmd.ru.1 %{buildroot}%{_mandir}/ru/man1/ydcmd.1
install -m644 man/ydcmd.tr.1 %{buildroot}%{_mandir}/tr/man1/ydcmd.1

%if 0%{?suse_version}
%py_compile -O %{buildroot}%{python_sitelib}
%fdupes %{buildroot}%{python_sitelib}
%endif


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)

%if 0%{?suse_version}
%dir %{_mandir}/tr
%dir %{_mandir}/tr/man1
%endif

%{_bindir}/ydcmd
%{python_sitelib}/ydcmd.py*

%doc %{_mandir}/man1/ydcmd.1*
%doc %{_mandir}/ru/man1/ydcmd.1*
%doc %{_mandir}/tr/man1/ydcmd.1*

%doc README.md README.en.md README.tr.md ydcmd.cfg


%changelog
* Tue May 16 2017 Anton Batenev <antonbatenev@yandex.ru> 2.10-1
- Initial RPM release
