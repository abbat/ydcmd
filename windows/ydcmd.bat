SET DST="build"
SET PYTHON="c:\projects\python34\python.exe"
SET UNIX2DOS="c:\projects\unix2dos\unix2dos.exe"

RMDIR /S /Q %DST%
MKDIR %DST%

COPY ..\ydcmd.py         %DST%\ydcmd.py
COPY ..\ydcmd.cfg        %DST%\ydcmd.cfg
COPY ..\debian\copyright %DST%\LICENSE.txt

COPY README.txt %DST%\README.txt
COPY setup.py   %DST%\setup.py

CD %DST%

%UNIX2DOS% ydcmd.py
%UNIX2DOS% ydcmd.cfg
%UNIX2DOS% LICENSE.txt

bitsadmin.exe /transfer "CA Root NSS" http://curl.haxx.se/ca/cacert.pem %CD%\ca-root.crt

%PYTHON% setup.py build
%PYTHON% setup.py bdist_msi
