Name:          ydcmd
Version:       0.4
Release:       1
BuildArch:     noarch
Summary:       Command line client for Yandex.Disk
Group:         Applications/Internet
License:       BSD-2-Clause
URL:           https://github.com/abbat/ydcmd
Requires:      python >= 2.6, python-dateutil
BuildRequires: python-devel >= 2.6

%if 0%{?suse_version}
BuildRequires: fdupes
%endif

Source0:       https://build.opensuse.org/source/home:antonbatenev:ydcmd/ydcmd/ydcmd_%{version}.tar.bz2
BuildRoot:     %{_tmppath}/%{name}-%{version}-build


%description
Command line client for interacting with cloud storage Yandex.Disk by means of REST API


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

install -m644 man/ydcmd.1    %{buildroot}%{_mandir}/man1/ydcmd.1
install -m644 man/ydcmd.ru.1 %{buildroot}%{_mandir}/ru/man1/ydcmd.1

%if 0%{?suse_version}
%py_compile -O %{buildroot}%{python_sitelib}
%fdupes %{buildroot}%{python_sitelib}
%endif


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)

%{_bindir}/ydcmd
%{python_sitelib}/ydcmd.py*

%doc %{_mandir}/man1/ydcmd.1%{?ext_man}
%doc %{_mandir}/ru/man1/ydcmd.1%{?ext_man}

%doc README.md README.en.md ydcmd.cfg


%changelog
* Mon Sep 01 2014 Anton Batenev <antonbatenev@yandex.ru> 0.3-1
- Initial RPM release
